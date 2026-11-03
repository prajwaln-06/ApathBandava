"""FR-12 static URL checks. Pure string analysis: this module never fetches anything (NFR-3)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

import idna
import tldextract
from rapidfuzz.distance import Levenshtein

from .registry import Registry, host_matches

# Offline PSL snapshot (no network); .bank.in/.fin.in are RBI-mandated suffixes; reserved TLDs
# are added so synthetic fixtures (.example/.test) parse like real domains.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), extra_suffixes=["bank.in", "fin.in", "example", "test", "invalid"])

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly",
    "rebrand.ly", "tiny.cc", "s.id", "t.ly", "v.gd", "bit.do", "shorte.st", "short.gy", "surl.li", "lnkd.in",
    "bl.ink", "tny.im", "u.to", "clck.ru", "qr.ae", "shrtco.de", "inx.lv", "rebrand.ly", "dub.sh", "l.ead.me",
}
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "live", "buzz", "cyou", "icu", "rest", "sbs", "cfd", "shop",
    "online", "site", "store", "monster", "quest", "tk", "ml", "ga", "cf", "gq", "lol", "work", "support",
    "help", "vip", "win", "bid", "loan", "date", "racing", "review", "country", "kim", "men", "party", "fun",
}
# Common confusables -> ASCII skeleton (Cyrillic/Greek lookalikes and digit swaps).
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g",
    "ӏ": "l", "ѕ": "s", "ԛ": "q", "ԝ": "w", "һ": "h", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "ε": "e",
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a",
})


def _with_scheme(url: str) -> str:
    url = url.strip()
    return url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url


def host_of(url: str) -> str:
    try:
        host = urlsplit(_with_scheme(url)).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def _ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # decimal / hex integer hosts such as http://3232235777 or 0x7f000001
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def _to_unicode(host: str) -> str:
    try:
        return idna.decode(host)
    except (idna.IDNAError, UnicodeError, ValueError):
        # IDNA2008 rejects some mixed-script labels; decode each xn-- label leniently instead.
        out = []
        for label in host.split("."):
            try:
                out.append(label[4:].encode("ascii").decode("punycode") if label.startswith("xn--") else label)
            except (UnicodeError, ValueError):
                out.append(label)
        return ".".join(out)


def skeleton(label: str) -> str:
    return label.lower().translate(CONFUSABLES).replace("rn", "m").replace("vv", "w")


def analyze(url: str, registry: Registry) -> dict[str, Any]:
    raw = _with_scheme(url)
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        parts, host = None, ""
    flags: list[str] = []
    out: dict[str, Any] = {"host": host, "registrable_domain": "", "tld": "", "punycode": False, "homoglyph_of": None,
                           "brand_in_subdomain": None, "shortener": False, "ip_host": False, "flags": flags}
    if not host:
        return out

    if parts is not None and "@" in (parts.netloc or ""):
        flags.append("AT_IN_URL")
    if _ip_host(host):
        out["ip_host"] = True
        flags.append("IP_HOST")
        return out

    unicode_host = _to_unicode(host)
    if "xn--" in host or unicode_host != host or any(ord(c) > 127 for c in host):
        out["punycode"] = True
        flags.append("PUNYCODE")

    ext = _EXTRACT(unicode_host)
    suffix = ext.suffix
    registrable = f"{ext.domain}.{suffix}" if ext.domain and suffix else unicode_host
    out["registrable_domain"] = registrable
    out["tld"] = suffix.split(".")[-1] if suffix else ""
    if out["tld"] in RISKY_TLDS:
        flags.append("RISKY_TLD")
    if registrable in SHORTENERS or host in SHORTENERS:
        out["shortener"] = True
        flags.append("SHORTENER")

    official = registry.official_domains()
    is_official = any(host_matches(host, d) or host_matches(unicode_host, d) for d, _ in official)
    if is_official:
        return out

    # Homoglyph: the skeleton of the host equals (or ends with) an official domain.
    skel = ".".join(skeleton(p) for p in unicode_host.split("."))
    for dom, name in official:
        if skel == dom or skel.endswith("." + dom):
            out["homoglyph_of"] = dom
            break
    tokens = registry.brand_tokens()
    sub = ext.subdomain.lower()
    path = (parts.path or "").lower() if parts else ""
    sub_tokens = set(re.split(r"[^a-z0-9]+", sub)) - {""}
    path_tokens = set(re.split(r"[^a-z0-9]+", path)) - {""}
    brand = next((name for tok, name in tokens.items()
                  if tok in sub_tokens or tok in path_tokens or (len(tok) >= 4 and tok in sub)), None)
    if brand is None and "bank.in" in sub:
        brand = "a bank (.bank.in in subdomain)"
    out["brand_in_subdomain"] = brand
    if out["homoglyph_of"] or out["brand_in_subdomain"]:
        flags.append("HOMOGLYPH_OR_BRAND_IN_SUBDOMAIN")

    # Lookalike registrable label: contains a brand token, or within edit distance 2 of an official label.
    label = skeleton(ext.domain)
    label_parts = set(re.split(r"[^a-z0-9]+", label))
    for dom, name in official:
        off = dom.split(".")[0]
        if len(off) >= 5 and Levenshtein.distance(label, off) <= 2 and label != off:
            flags.append("LOOKALIKE_DOMAIN")
            break
    else:
        if any(tok in label_parts or (len(tok) >= 4 and tok in label) for tok in tokens):
            flags.append("LOOKALIKE_DOMAIN")
    return out
