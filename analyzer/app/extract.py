"""FR-8..FR-11 artifact extraction: regex over text + OCR (Tesseract eng+hin) + QR decode."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from .registry import Registry
from .url_static import _EXTRACT

log = logging.getLogger(__name__)

MAX_IMAGE_BYTES = 10 * 1024 * 1024
TRAILING = ".,;:!?)]}'\"…>"

UPI_URI_RX = re.compile(r"upi://[^\s<>\"'`]+", re.I)
URL_RX = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+", re.I)
BARE_RX = re.compile(r"(?<![@\w.\-/])((?:[\w\-]+\.)+[\w\-]{2,})(/[^\s<>\"'`]*)?", re.U)
UPI_ID_RX = re.compile(r"(?<![\w.\-])([A-Za-z0-9][\w.\-]{1,255}@[A-Za-z][A-Za-z0-9]{1,63})(?![A-Za-z0-9]|\.[A-Za-z])")
MOBILE_RX = re.compile(r"(?<![\d\w])(?:\+?91[\s\-]?|0)?([6-9]\d{4}[\s\-]?\d{5})(?!\d)")
SPECIAL_RX = re.compile(r"(?<!\d)(1800[\s\-]?\d{3,4}[\s\-]?\d{3,4}|1860[\s\-]?\d{3}[\s\-]?\d{4}|1600[\s\-]?\d{2,3}[\s\-]?\d{3,4}|1930)(?!\d)")
SENDER_RX = re.compile(r"\b([A-Z]{2}-[A-Z0-9]{6}(?:-[PSTG])?)\b")
AMOUNT_RX = re.compile(r"(?:₹|\brs\.?|\binr)\s*([0-9][0-9,]*(?:\.\d{1,2})?)", re.I)


class ImagePathError(ValueError):
    pass


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [x for x in items if not (x in seen or seen.add(x))]


def _clean(token: str) -> str:
    return token.rstrip(TRAILING)


def extract_urls(text: str) -> list[str]:
    text = UPI_URI_RX.sub(" ", text or "")
    found = [_clean(m.group(0)) for m in URL_RX.finditer(text)]
    covered = URL_RX.sub(" ", text)
    covered = UPI_ID_RX.sub(" ", covered)
    for m in BARE_RX.finditer(covered):
        cand = _clean(m.group(0))
        host = cand.split("/")[0]
        if re.fullmatch(r"[\d.]+", host):
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
                found.append(cand)  # IPv4 literal
            continue
        ext = _EXTRACT(host)
        if ext.domain and ext.suffix and not ext.domain.isdigit() and len(ext.domain) > 1:
            found.append(cand)
    return _dedupe(found)


def extract_phones(text: str) -> list[str]:
    out = []
    for m in SPECIAL_RX.finditer(text or ""):
        out.append(re.sub(r"\D", "", m.group(1)))
    for m in MOBILE_RX.finditer(text or ""):
        out.append("+91" + re.sub(r"\D", "", m.group(1)))
    return _dedupe(out)


def extract_amounts(text: str) -> list[float]:
    out: list[float] = []
    for m in AMOUNT_RX.finditer(text or ""):
        try:
            val = float(m.group(1).replace(",", ""))
        except ValueError:  # pragma: no cover - regex guarantees digits
            continue
        if val not in out:
            out.append(val)
    return out


def safe_image_path(image_path: str, media_dir: str) -> Path:
    """Only files inside MEDIA_DIR (comma-separated roots) may be read (no traversal, no symlink escape)."""
    roots = [Path(r.strip()).resolve() for r in media_dir.split(",") if r.strip()]
    candidate = Path(image_path)
    if not candidate.is_absolute():
        candidate = roots[0] / candidate
    resolved = candidate.resolve()
    if not any(root == resolved or root in resolved.parents for root in roots):
        raise ImagePathError("image_path must be inside the media directory")
    if not resolved.is_file():
        raise ImagePathError("image not found")
    if resolved.stat().st_size > MAX_IMAGE_BYTES:
        raise ImagePathError("image too large")
    return resolved


def ocr_and_qr(path: Path) -> tuple[str, list[str]]:
    from PIL import Image

    with Image.open(path) as im:
        im.load()
        img = im.convert("RGB")
    qr = decode_qr(img)
    return run_ocr(img), qr


def run_ocr(img: Any) -> str:
    import pytesseract

    gray = img.convert("L")
    if gray.width < 1000:
        gray = gray.resize((gray.width * 2, gray.height * 2))
    try:
        return pytesseract.image_to_string(gray, lang=os.getenv("OCR_LANGS", "eng+hin"), timeout=15).strip()
    except Exception as exc:  # noqa: BLE001 - OCR failure must not block a verdict (NFR-8)
        log.warning("ocr failed: %s", exc)
        return ""


def decode_qr(img: Any) -> list[str]:
    payloads: list[str] = []
    try:
        from pyzbar.pyzbar import decode

        payloads = [d.data.decode("utf-8", "replace") for d in decode(img)]
    except Exception as exc:  # noqa: BLE001
        log.warning("pyzbar failed: %s", exc)
    if not payloads:
        try:
            import cv2
            import numpy as np

            ok, decoded, _, _ = cv2.QRCodeDetector().detectAndDecodeMulti(np.array(img)[:, :, ::-1])
            payloads = [d for d in decoded if d] if ok else []
        except Exception as exc:  # noqa: BLE001
            log.warning("opencv qr failed: %s", exc)
    return _dedupe(payloads)


WRAPPED_URL = re.compile(r"([\w/:]*[\w-]\.[\w.-]*[-./])[ \t]*\n[ \t]*(?=[\w-]+[./])")


def join_wrapped_urls(text: str) -> str:
    """Screenshots wrap long links ("sbi.bank.in-\\nkyc-update.example"); re-join them for extraction."""
    return WRAPPED_URL.sub(r"\1", text or "")


def extract(text: str, registry: Registry, image_path: str | None = None, media_dir: str = "/media") -> dict[str, Any]:
    ocr_text, qr_payloads = "", []
    if image_path:
        ocr_text, qr_payloads = ocr_and_qr(safe_image_path(image_path, media_dir))
    corpus = "\n".join([text or "", join_wrapped_urls(ocr_text), *qr_payloads])
    upi_uris = _dedupe([_clean(m.group(0)) for m in UPI_URI_RX.finditer(corpus)])
    urls = extract_urls(corpus)
    upi_ids = _dedupe([m.group(1) for m in UPI_ID_RX.finditer(UPI_URI_RX.sub(" ", URL_RX.sub(" ", corpus)))])
    for uri in upi_uris:
        m = re.search(r"[?&]pa=([^&\s]+)", uri)
        if m and m.group(1) not in upi_ids:
            upi_ids.append(m.group(1))
    return {
        "urls": urls,
        "upi_uris": upi_uris,
        "upi_ids": upi_ids,
        "phones": extract_phones(corpus),
        "sender_ids": _dedupe(SENDER_RX.findall(corpus)),
        "amounts": extract_amounts(corpus),
        "brands": registry.find_brands(corpus),
        "ocr_text": ocr_text,
        "qr_payloads": qr_payloads,
    }
