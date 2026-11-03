"""OpenAI-compatible LLM gateway for ScamSaathi.

n8n's AI Agent nodes talk to this service with the OpenAI Chat Model node. The gateway
holds the provider credentials (NFR-4: n8n never sees them) and forwards to the provider
chosen by env:

  LLM_PROVIDER=vertex   -> Vertex AI OpenAI-compatible endpoint, service-account auth
  LLM_PROVIDER=openai_compat -> any OpenAI-compatible base URL (Gemini AI Studio, OpenAI,
                               Anthropic, ...) with LLM_BASE_URL + LLM_API_KEY

It also re-attaches Gemini 3 "thought signatures" to replayed assistant tool calls, which
LangChain drops between agent iterations (Vertex rejects tool turns without them).
Prompts and completions are never logged (NFR-10); only latency, status and tool names.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

log = logging.getLogger("llm-gateway")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

PROVIDER = os.getenv("LLM_PROVIDER", "vertex")
MODEL = os.getenv("LLM_MODEL", "gemini-3.5-flash")
TOKEN = os.getenv("LLM_GATEWAY_TOKEN", "")
TIMEOUT = float(os.getenv("LLM_TIMEOUT_S", "20"))
GCP_PROJECT = os.getenv("GCP_PROJECT", "")
GCP_LOCATION = os.getenv("GCP_LOCATION", "global")
BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
API_KEY = os.getenv("LLM_API_KEY", "")
REASONING_EFFORT = os.getenv("LLM_REASONING_EFFORT", "")  # e.g. "low" for latency (NFR-6)

ALLOWED_KEYS = {
    "model", "messages", "tools", "tool_choice", "temperature", "top_p", "max_tokens",
    "stop", "n", "seed", "response_format", "reasoning_effort",
}
DUMMY_SIGNATURE = {"google": {"thought_signature": "skip_thought_signature_validator"}}

app = FastAPI(title="llm-gateway")


class _SigCache:
    """Bounded map tool_call_id -> extra_content (thought signature)."""

    def __init__(self, size: int = 5000) -> None:
        self._d: OrderedDict[str, Any] = OrderedDict()
        self._size = size
        self._lock = threading.Lock()

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._d[key] = value
            self._d.move_to_end(key)
            while len(self._d) > self._size:
                self._d.popitem(last=False)

    def get(self, key: str) -> Any:
        with self._lock:
            return self._d.get(key)


SIGS = _SigCache()
_creds = None
_creds_lock = threading.Lock()


def _vertex_token() -> str:
    global _creds
    import google.auth
    from google.auth.transport.requests import Request as GRequest

    with _creds_lock:
        if _creds is None:
            _creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        if not _creds.valid:
            _creds.refresh(GRequest())
        return _creds.token


def upstream() -> tuple[str, dict[str, str], str]:
    if PROVIDER == "vertex":
        host = "aiplatform.googleapis.com" if GCP_LOCATION == "global" else f"{GCP_LOCATION}-aiplatform.googleapis.com"
        url = f"https://{host}/v1/projects/{GCP_PROJECT}/locations/{GCP_LOCATION}/endpoints/openapi/chat/completions"
        model = MODEL if "/" in MODEL else f"google/{MODEL}"
        return url, {"Authorization": f"Bearer {_vertex_token()}"}, model
    if PROVIDER == "openai_compat":
        return f"{BASE_URL}/chat/completions", {"Authorization": f"Bearer {API_KEY}"}, MODEL
    raise HTTPException(500, f"unsupported LLM_PROVIDER {PROVIDER}")


def prepare(body: dict[str, Any], model: str) -> dict[str, Any]:
    out = {k: v for k, v in body.items() if k in ALLOWED_KEYS}
    if "max_completion_tokens" in body and "max_tokens" not in out:
        out["max_tokens"] = body["max_completion_tokens"]
    out["model"] = model
    if REASONING_EFFORT and "reasoning_effort" not in out:
        out["reasoning_effort"] = REASONING_EFFORT
    for msg in out.get("messages", []):
        if msg.get("role") == "assistant":
            for call in msg.get("tool_calls") or []:
                if "extra_content" not in call:
                    call["extra_content"] = SIGS.get(call.get("id", "")) or DUMMY_SIGNATURE
    return out


def remember(resp: dict[str, Any]) -> None:
    for choice in resp.get("choices", []):
        for call in (choice.get("message") or {}).get("tool_calls") or []:
            if call.get("id") and call.get("extra_content"):
                SIGS.put(call["id"], call["extra_content"])


def check_auth(request: Request) -> None:
    if TOKEN and request.headers.get("authorization", "") != f"Bearer {TOKEN}":
        raise HTTPException(401, "bad gateway token")


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "provider": PROVIDER, "model": MODEL}


@app.get("/v1/models")
def models(request: Request) -> dict[str, Any]:
    check_auth(request)
    return {"object": "list", "data": [{"id": MODEL, "object": "model", "owned_by": PROVIDER}]}


def _sse(resp: dict[str, Any]):
    """Re-emit a non-streaming completion as one SSE chunk sequence."""
    for choice in resp.get("choices", []):
        msg = choice.get("message") or {}
        delta: dict[str, Any] = {"role": "assistant", "content": msg.get("content")}
        if msg.get("tool_calls"):
            delta["tool_calls"] = [dict(c, index=i) for i, c in enumerate(msg["tool_calls"])]
        chunk = {"id": resp.get("id"), "object": "chat.completion.chunk", "created": resp.get("created"),
                 "model": resp.get("model"), "choices": [{"index": choice.get("index", 0), "delta": delta,
                                                           "finish_reason": choice.get("finish_reason")}]}
        yield f"data: {json.dumps(chunk)}\n\n"
    if resp.get("usage"):
        yield f"data: {json.dumps({'id': resp.get('id'), 'object': 'chat.completion.chunk', 'choices': [], 'usage': resp['usage']})}\n\n"
    yield "data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def chat(request: Request):
    check_auth(request)
    body = await request.json()
    stream = bool(body.get("stream"))
    url, headers, model = upstream()
    payload = prepare(body, model)
    tools = [t.get("function", {}).get("name") for t in payload.get("tools", [])]
    t0 = time.monotonic()
    resp = None
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for attempt in range(2):
            try:
                resp = await client.post(url, headers=headers, json=payload)
            except httpx.TimeoutException:
                raise HTTPException(504, "upstream timeout")
            if resp.status_code not in (429, 500, 502, 503) or attempt == 1:
                break
    ms = int((time.monotonic() - t0) * 1000)
    log.info("chat model=%s status=%s ms=%s tools=%s stream=%s", model, resp.status_code, ms, tools, stream)
    if resp.status_code != 200:
        log.warning("upstream error: %s", resp.text[:500])
        return JSONResponse(status_code=resp.status_code, content={"error": {"message": resp.text[:500]}})
    data = resp.json()
    remember(data)
    if stream:
        return StreamingResponse(_sse(data), media_type="text/event-stream")
    return data
