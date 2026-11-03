"""Mock WhatsApp bridge for tests/eval: records /api/send calls instead of sending (bridge mocked)."""
import hmac
import os
import time

from fastapi import FastAPI, Header, HTTPException

app = FastAPI()
SENT: list[dict] = []
TOKEN = os.getenv("BRIDGE_TOKEN", "")


@app.get("/api/health")
def health():
    return {"status": "ok", "connected": True, "logged_in": True, "mock": True}


@app.post("/api/send")
def send(body: dict, x_bridge_token: str = Header(default="")):
    if not TOKEN or not hmac.compare_digest(x_bridge_token, TOKEN):
        raise HTTPException(401, "unauthorized")
    SENT.append({"recipient": body.get("recipient"), "message": body.get("message"), "at": time.time()})
    return {"success": True, "message": "recorded"}


@app.get("/sent")
def sent(recipient: str | None = None):
    return [m for m in SENT if recipient is None or m["recipient"] == recipient]


@app.delete("/sent")
def clear():
    SENT.clear()
    return {"cleared": True}
