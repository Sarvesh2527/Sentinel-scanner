"""
sensitive_data_check.py -- Sensitive data / secret exposure (OWASP A02).

Scans the page source (HTML, inline JS, comments) for secrets that should never
be shipped to the browser: cloud API keys, private keys, tokens and JWTs, plus
lower-severity leaks like internal IP addresses. Purely passive pattern-matching
on the response body.
"""

from __future__ import annotations

import re

from ._common import (
    fetch, result, SEV_HIGH, SEV_LOW,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
)

NAME = "Sensitive Data Exposure"
CATEGORY = "VA"
OWASP = "A02: Cryptographic Failures"
TIMEOUT = 10

# (label, regex, is_high_severity). High-severity ones are real secrets.
SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}"), True),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), True),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), True),
    ("Stripe live secret key", re.compile(r"sk_live_[0-9A-Za-z]{16,}"), True),
    ("GitHub token", re.compile(r"ghp_[0-9A-Za-z]{36}"), True),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), True),
    ("JSON Web Token (JWT)", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), True),
    ("Hardcoded secret assignment",
     re.compile(r"""(?:api[_-]?key|secret|passwd|password|access[_-]?token)["']?\s*[:=]\s*["'][^"']{8,}["']""", re.I), True),
    ("Internal IP address",
     re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"), False),
]


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("sensitive_data", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not fetch the page to inspect for secrets -- {err or 'no response'}.")

    body = resp.text or ""
    high, low = [], []
    for label, rx, is_high in SECRET_PATTERNS:
        m = rx.search(body)
        if not m:
            continue
        # redact the match in the evidence so we don't echo the full secret
        snippet = m.group(0)
        shown = snippet[:6] + "…" + snippet[-2:] if len(snippet) > 12 else snippet[:4] + "…"
        (high if is_high else low).append(f"{label}: {shown}")

    if high:
        return result("sensitive_data", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
                      f"{len(high)} secret(s) exposed in the page source.",
                      high + low + ["Move secrets server-side; never ship keys to the browser."])
    if low:
        return result("sensitive_data", NAME, CATEGORY, STATUS_WARN, SEV_LOW,
                      "Internal information disclosed in the page source.",
                      low + ["Avoid leaking internal IPs / infrastructure details to clients."])

    return result("sensitive_data", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  "No exposed secrets or internal data found in the page source.",
                  ["Scanned HTML, inline scripts and comments for key/token patterns."])
