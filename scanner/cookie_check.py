"""
cookie_check.py -- insecure cookie flags (OWASP A05 / A07).

Session cookies should be marked `Secure` (HTTPS-only), `HttpOnly` (not readable
from JavaScript, limiting XSS impact) and `SameSite` (CSRF mitigation). We read
the cookies the server sets and report any that are missing these flags.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
)

NAME = "Cookie Security"
CATEGORY = "VA"
OWASP = "A05: Security Misconfiguration"

TIMEOUT = 8


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("cookies", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not read cookies -- {err or 'no response'}.")

    is_https = urlparse(resp.url).scheme == "https"
    cookies = list(resp.cookies)

    if not cookies:
        return result("cookies", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                      "No cookies were set on the initial response.",
                      ["Nothing to flag."])

    problems, evidence = [], []
    for c in cookies:
        missing = []
        if is_https and not c.secure:
            missing.append("Secure")
        # requests stores non-standard attributes in c._rest (case-insensitive)
        rest = {k.lower() for k in getattr(c, "_rest", {}).keys()}
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if "samesite" not in rest:
            missing.append("SameSite")
        if missing:
            problems.append(c.name)
            evidence.append(f"{c.name}: missing {', '.join(missing)}")
        else:
            evidence.append(f"{c.name}: Secure + HttpOnly + SameSite (OK)")

    if problems:
        return result("cookies", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                      f"{len(problems)} cookie(s) missing security flags: {', '.join(problems)}.",
                      evidence)

    return result("cookies", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  f"All {len(cookies)} cookie(s) set Secure, HttpOnly and SameSite.",
                  evidence)
