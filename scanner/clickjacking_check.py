"""
clickjacking_check.py -- Clickjacking exposure (OWASP A05).

A page an attacker can load inside an invisible <iframe> can be used for
clickjacking (UI redressing). The defences are an `X-Frame-Options` header
(DENY / SAMEORIGIN) or a CSP `frame-ancestors` directive. If neither is present,
the page can be framed by any site.
"""

from __future__ import annotations

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
)

NAME = "Clickjacking"
CATEGORY = "VA"
OWASP = "A05: Security Misconfiguration"
TIMEOUT = 8


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("clickjacking", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not test framing protection -- {err or 'no response'}.")

    xfo = resp.headers.get("X-Frame-Options", "").strip()
    csp = resp.headers.get("Content-Security-Policy", "").lower()
    has_frame_ancestors = "frame-ancestors" in csp

    if xfo or has_frame_ancestors:
        ev = []
        if xfo:
            ev.append(f"X-Frame-Options: {xfo}")
        if has_frame_ancestors:
            ev.append("CSP frame-ancestors directive present")
        return result("clickjacking", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                      "Framing is restricted -- clickjacking is mitigated.", ev)

    return result("clickjacking", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                  "Page can be framed by any site -- vulnerable to clickjacking.",
                  ["No X-Frame-Options header and no CSP frame-ancestors directive.",
                   "Add 'X-Frame-Options: DENY' or CSP \"frame-ancestors 'none'\"."])
