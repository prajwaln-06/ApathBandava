"""FR-8..FR-11: extraction (regex, OCR eng+hin, QR decode) and the media path guard."""
import pytest
from PIL import Image, ImageDraw, ImageFont

from app import extract as ex


def test_text_artifacts(registry):
    text = ("Dear SBI customer, your YONO KYC expired. Update at http://sbi-kyc-update.example/login or www.sbi.co.in "
            "or bare hdfc-secure.example/verify. Pay Rs. 1,499.50 or ₹25 to refund.desk@ybl, call +91 98765 43210 or "
            "1800 1234 567. Sender VM-SBIBNK-S. Mail me at a.person@gmail.com. upi://pay?pa=fraud@ybl&pn=Refund&am=1499")
    out = ex.extract(text, registry)
    assert "http://sbi-kyc-update.example/login" in out["urls"]
    assert "www.sbi.co.in" in out["urls"]
    assert "hdfc-secure.example/verify" in out["urls"]
    assert not any("gmail" in u for u in out["urls"])  # email domains are not links
    assert out["upi_uris"] == ["upi://pay?pa=fraud@ybl&pn=Refund&am=1499"]
    assert "refund.desk@ybl" in out["upi_ids"] and "fraud@ybl" in out["upi_ids"]
    assert "a.person@gmail" not in " ".join(out["upi_ids"])
    assert "+919876543210" in out["phones"] and "18001234567" in out["phones"]
    assert out["sender_ids"] == ["VM-SBIBNK-S"]
    assert 1499.5 in out["amounts"] and 25.0 in out["amounts"]
    assert out["brands"][0] == "State Bank of India"
    assert out["ocr_text"] == "" and out["qr_payloads"] == []


def test_ip_literal_and_noise(registry):
    out = ex.extract("open 192.168.1.10/x and http://10.0.0.1 not e.g. or Rs.500 or 3.14 or No.1", registry)
    assert "192.168.1.10/x" in out["urls"] and "http://10.0.0.1" in out["urls"]
    assert len(out["urls"]) == 2


def test_special_numbers(registry):
    out = ex.extract("Call 1930 or 1600-123-4567 or 1860 266 9966 or 09876543210", registry)
    assert {"1930", "16001234567", "18602669966", "+919876543210"} <= set(out["phones"])


def test_brand_longest_match(registry):
    assert registry.find_brands("HDFC Life policy") == ["HDFC Life"]
    assert registry.find_brands("State Bank of India and Bank of India") == ["State Bank of India", "Bank of India"]
    assert registry.find_brands("public click") == []


def _font(size):
    for path in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            pass
    return ImageFont.load_default()


@pytest.fixture
def media(tmp_path):
    return tmp_path


def test_image_ocr_and_qr(media, registry):
    import qrcode

    img = Image.new("RGB", (900, 500), "white")
    ImageDraw.Draw(img).text((30, 30), "SCAN TO RECEIVE REFUND", fill="black", font=_font(40))
    qr = qrcode.make("upi://pay?pa=refund.help@ybl&pn=Refund%20Desk&am=1499&tn=refund").convert("RGB").resize((330, 330))
    img.paste(qr, (520, 140))
    path = media / "qr.png"
    img.save(path)
    out = ex.extract("", registry, image_path=str(path), media_dir=str(media))
    assert "REFUND" in out["ocr_text"].upper()
    assert out["qr_payloads"][0].startswith("upi://pay")
    assert "refund.help@ybl" in out["upi_ids"]


def test_qr_opencv_fallback(monkeypatch):
    import qrcode

    img = qrcode.make("https://example.org/x").convert("RGB")
    import pyzbar.pyzbar as pz

    monkeypatch.setattr(pz, "decode", lambda *_: (_ for _ in ()).throw(RuntimeError("no zbar")))
    assert ex.decode_qr(img) == ["https://example.org/x"]


def test_ocr_failure_returns_empty(monkeypatch):
    import pytesseract

    monkeypatch.setattr(pytesseract, "image_to_string", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert ex.run_ocr(Image.new("RGB", (10, 10))) == ""


def test_qr_both_decoders_fail(monkeypatch):
    import cv2
    import pyzbar.pyzbar as pz

    monkeypatch.setattr(pz, "decode", lambda *_: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(cv2, "QRCodeDetector", lambda: (_ for _ in ()).throw(RuntimeError("y")))
    assert ex.decode_qr(Image.new("RGB", (10, 10))) == []


def test_media_path_guard(media):
    (media / "ok.png").write_bytes(b"x")
    assert ex.safe_image_path("ok.png", str(media)).name == "ok.png"
    assert ex.safe_image_path(str(media / "ok.png"), f"/nonexistent,{media}").name == "ok.png"
    with pytest.raises(ex.ImagePathError):
        ex.safe_image_path("../../etc/passwd", str(media))
    with pytest.raises(ex.ImagePathError):
        ex.safe_image_path("/etc/passwd", str(media))
    with pytest.raises(ex.ImagePathError):
        ex.safe_image_path("missing.png", str(media))
    big = media / "big.png"
    big.write_bytes(b"0" * (ex.MAX_IMAGE_BYTES + 1))
    with pytest.raises(ex.ImagePathError):
        ex.safe_image_path("big.png", str(media))


def test_wrapped_ocr_urls_rejoined():
    assert ex.join_wrapped_urls("Update now: https://sbi.bank.in-\nkyc-update.example/yono and") == \
        "Update now: https://sbi.bank.in-kyc-update.example/yono and"
    assert ex.join_wrapped_urls("visit www.hdfc-\npoints.example now") == "visit www.hdfc-points.example now"
    assert ex.join_wrapped_urls("Dear customer.\nYour account") == "Dear customer.\nYour account"


def test_d1_fixture_image(registry):
    out = ex.extract("", registry, image_path="d1_sbi_kyc_sms.png", media_dir="/repo/tests/fixtures/images")
    assert any("in-kyc-update.example" in u for u in out["urls"]), out
    assert "AD-SBIUPD-S" in out["sender_ids"] and "State Bank of India" in out["brands"]


def test_d2_fixture_qr(registry):
    out = ex.extract("", registry, image_path="d2_refund_qr.png", media_dir="/repo/tests/fixtures/images")
    assert out["upi_uris"] and "am=1499" in out["upi_uris"][0]
