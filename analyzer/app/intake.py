"""Intake guard: FR-3 dedupe + group/status filter, FR-4 rate limit, FR-5 commands, FR-6 off-topic.

Runs before any LLM sees the message. Uses Redis for dedupe, rate-limit counters and the
per-sender language preference (keyed by the salted sender hash, never the raw number).
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any

from . import patterns
from .extract import extract_phones, extract_urls
from .store import sender_hash

TEXT = {
    "en": {
        "help": ("ScamSaathi checks suspicious messages before you act.\n"
                 "Forward me an SMS, WhatsApp message, link, screenshot or QR image and I'll tell you if it shows signs of a scam.\n"
                 "Commands: hindi, english, report, help"),
        "lang": "OK, I'll reply in English.",
        "report": ("How to report a scam in India:\n"
                   "• Money lost? Call 1930 immediately (National Cyber Crime Helpline)\n"
                   "• File a complaint at cybercrime.gov.in\n"
                   "• Report the fraud number/SMS on Sanchar Saathi → Chakshu (sancharsaathi.gov.in)\n"
                   "• Call your bank's official helpline (from the back of your card or its .bank.in website) to block cards/UPI"),
        "offtopic": "I only check messages, links, screenshots and QR codes for scams. Forward me something suspicious, or type 'help'.",
        "ratelimited": "You've sent a lot of checks this hour. Please try again in a little while. Lost money? Call 1930 now.",
        "unsupported": "I can check text messages, links, screenshots and QR images. Voice notes, videos and documents aren't supported yet.",
        "checking": "Checking… ⏳",
    },
    "hi": {
        "help": ("ScamSaathi संदिग्ध संदेशों की जाँच करता है।\n"
                 "कोई SMS, WhatsApp संदेश, लिंक, स्क्रीनशॉट या QR फ़ोटो मुझे फ़ॉरवर्ड करें, मैं बताऊँगा कि उसमें धोखाधड़ी के संकेत हैं या नहीं।\n"
                 "कमांड: hindi, english, report, help"),
        "lang": "ठीक है, मैं हिंदी में जवाब दूँगा।",
        "report": ("भारत में धोखाधड़ी की शिकायत कैसे करें:\n"
                   "• पैसे गए? तुरंत 1930 पर कॉल करें\n"
                   "• cybercrime.gov.in पर शिकायत दर्ज करें\n"
                   "• संचार साथी → चक्षु (sancharsaathi.gov.in) पर नंबर/SMS की रिपोर्ट करें\n"
                   "• कार्ड/UPI बंद कराने के लिए अपने बैंक की आधिकारिक हेल्पलाइन पर कॉल करें"),
        "offtopic": "मैं सिर्फ़ संदेश, लिंक, स्क्रीनशॉट और QR कोड में धोखाधड़ी की जाँच करता हूँ। कुछ संदिग्ध फ़ॉरवर्ड करें या 'help' लिखें।",
        "ratelimited": "इस घंटे आपने बहुत जाँचें भेजी हैं। थोड़ी देर बाद फिर कोशिश करें। पैसे गए हों तो अभी 1930 पर कॉल करें।",
        "unsupported": "मैं टेक्स्ट, लिंक, स्क्रीनशॉट और QR फ़ोटो जाँच सकता हूँ। वॉइस नोट, वीडियो और दस्तावेज़ अभी समर्थित नहीं हैं।",
        "checking": "जाँच हो रही है… ⏳",
    },
}
COMMANDS = {"help": "help", "madad": "help", "मदद": "help", "hindi": "hi", "हिंदी": "hi", "हिन्दी": "hi",
            "english": "en", "angrezi": "en", "report": "report", "शिकायत": "report", "start": "help", "hi": "help",
            "hello": "help", "menu": "help"}
DEVANAGARI = re.compile(r"[ऀ-ॿ]")
GROUP_SERVERS = ("@g.us", "@broadcast", "@newsletter")


def detect_language(text: str) -> str:
    letters = [c for c in text or "" if c.isalpha()]
    if letters and sum(1 for c in letters if DEVANAGARI.match(c)) / len(letters) > 0.3:
        return "hi"
    return "en"


def is_offtopic(text: str) -> bool:
    if not text or len(text) > 300:
        return False
    if extract_urls(text) or extract_phones(text) or "@" in text or re.search(r"\d{4,}", text):
        return False
    return not patterns.has_scam_keywords(text)


async def guard(redis: Any, payload: dict[str, Any], salt: str, rate_limit: int) -> dict[str, Any]:
    jid = str(payload.get("sender_jid") or "")
    shash = sender_hash(jid, salt)
    trace_id = str(uuid.uuid4())
    base = {"sender_hash": shash, "trace_id": trace_id, "reply": None}
    text = (payload.get("text") or payload.get("caption") or "").strip()

    if payload.get("chat_type", "direct") != "direct" or jid.endswith(GROUP_SERVERS) or not jid:
        return {**base, "action": "ignore", "reason": "not_direct", "language": "en"}
    msg_id = str(payload.get("msg_id") or "")
    if msg_id and not await redis.set(f"dedupe:{msg_id}", "1", nx=True, ex=86400):
        return {**base, "action": "ignore", "reason": "duplicate", "language": "en"}

    stored = await redis.get(f"lang:{shash}")
    lang = (stored.decode() if isinstance(stored, bytes) else stored) or detect_language(text)
    lang = lang if lang in TEXT else "en"

    cmd = COMMANDS.get(text.lower().strip(" !.?")) if payload.get("type") == "text" else None
    if cmd in ("hi", "en"):
        await redis.set(f"lang:{shash}", cmd)
        return {**base, "action": "reply", "reason": "command", "language": cmd, "reply": TEXT[cmd]["lang"]}
    if cmd:
        return {**base, "action": "reply", "reason": "command", "language": lang, "reply": TEXT[lang][cmd]}

    bucket = f"rl:{shash}:{int(time.time() // 3600)}"
    count = await redis.incr(bucket)
    if count == 1:
        await redis.expire(bucket, 3600)
    if count > rate_limit:
        if count == rate_limit + 1:
            return {**base, "action": "reply", "reason": "rate_limited", "language": lang, "reply": TEXT[lang]["ratelimited"]}
        return {**base, "action": "ignore", "reason": "rate_limited", "language": lang}

    mtype = payload.get("type")
    if mtype not in ("text", "image"):
        return {**base, "action": "reply", "reason": "unsupported", "language": lang, "reply": TEXT[lang]["unsupported"]}
    if mtype == "text" and is_offtopic(text):
        return {**base, "action": "reply", "reason": "offtopic", "language": lang, "reply": TEXT[lang]["offtopic"]}
    return {**base, "action": "check", "reason": "ok", "language": lang, "checking": TEXT[lang]["checking"]}
