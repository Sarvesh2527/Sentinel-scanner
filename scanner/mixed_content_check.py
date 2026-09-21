"""
mixed_content_check.py -- Mixed content (OWASP A02).

An HTTPS page that pulls resources over plain http:// breaks the security
guarantees of TLS. *Active* mixed content (scripts, iframes, form posts) is the
worst -- it can be tampered with in transit to run attacker code. *Passive*
mixed content (images, media) is lower risk. Only meaningful on HTTPS pages.
"""

from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_MEDIUM, SEV_LOW,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
)

NAME = "Mixed Content"
CATEGORY = "VA"
OWASP = "A02: Cryptographic Failures"
TIMEOUT = 10


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("mixed_content", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not fetch the page -- {err or 'no response'}.")

    if urlparse(resp.url).scheme != "https":
        return result("mixed_content", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      "Page is served over HTTP, so mixed content does not apply.",
                      ["(The HTTPS Usage check covers the lack of TLS here.)"])

    soup = BeautifulSoup(resp.text or "", "html.parser")
    active, passive = [], []

    for tag, attr, kind in [("script", "src", active), ("iframe", "src", active),
                            ("link", "href", active), ("form", "action", active),
                            ("img", "src", passive), ("audio", "src", passive),
                            ("video", "src", passive), ("source", "src", passive)]:
        for el in soup.find_all(tag):
            val = el.get(attr, "")
            if val.startswith("http://"):
                kind.append(f"<{tag} {attr}> {val[:80]}")

    if active:
        return result("mixed_content", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                      f"HTTPS page loads {len(active)} active resource(s) over http://.",
                      active[:10] + (["+ passive: " + str(len(passive))] if passive else []))
    if passive:
        return result("mixed_content", NAME, CATEGORY, STATUS_WARN, SEV_LOW,
                      f"HTTPS page loads {len(passive)} passive resource(s) over http://.",
                      passive[:10])

    return result("mixed_content", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  "No http:// resources loaded on this HTTPS page.",
                  ["All scripts, frames, images and media use HTTPS or relative URLs."])
