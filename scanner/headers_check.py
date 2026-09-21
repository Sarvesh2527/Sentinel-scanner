"""
headers_check.py -- fetches response headers and checks for the key security
headers: Content-Security-Policy, X-Frame-Options, Strict-Transport-Security,
X-Content-Type-Options and Referrer-Policy.

Missing security headers do not break a site, but they remove important
browser-side defences (clickjacking protection, MIME sniffing protection,
forced HTTPS, XSS mitigation). We report how many of the important headers
are present and fail if the critical ones are missing.
"""

from __future__ import annotations

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
)

NAME = "Security Headers"
CATEGORY = "VA"

# Header -> short reason it matters. Order roughly by importance.
IMPORTANT_HEADERS = {
    "content-security-policy": "restricts where scripts/resources can load from",
    "strict-transport-security": "forces browsers to always use HTTPS",
    "x-frame-options": "blocks clickjacking via framing",
    "x-content-type-options": "stops MIME-type sniffing",
    "referrer-policy": "controls how much referrer info leaks",
}

# These two carry the most weight -- if both are missing it's a real gap.
CRITICAL = {"content-security-policy", "x-frame-options"}


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result(
            "headers", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
            f"Could not read response headers -- {err}.",
        )

    # requests header lookup is case-insensitive already, but normalise for our
    # own set maths.
    present = {h.lower() for h in resp.headers.keys()}

    found = [h for h in IMPORTANT_HEADERS if h in present]
    missing = [h for h in IMPORTANT_HEADERS if h not in present]

    evidence = [f"Present: {h}" for h in found] + \
               [f"Missing: {h} ({IMPORTANT_HEADERS[h]})" for h in missing]

    total = len(IMPORTANT_HEADERS)
    got = len(found)
    critical_missing = CRITICAL - present

    if got == total:
        return result(
            "headers", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
            f"All {total} key security headers are present.",
            evidence,
        )
    if critical_missing:
        return result(
            "headers", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
            f"Missing critical headers ({got}/{total} present): "
            + ", ".join(sorted(critical_missing)) + ".",
            evidence,
        )
    # Only lower-impact headers missing -> a warning, not a hard fail.
    return result(
        "headers", NAME, CATEGORY, STATUS_WARN, SEV_MEDIUM,
        f"Some hardening headers missing ({got}/{total} present).",
        evidence,
    )
