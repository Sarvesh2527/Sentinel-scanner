"""
host_header_check.py -- Host header injection (OWASP A03).

Some apps trust the incoming Host / X-Forwarded-Host header when building
absolute URLs (password-reset links, redirects, cached pages). If an attacker
can set that value, they can poison reset emails or the cache. We send a spoofed
host and check whether it comes back in a redirect Location or absolute link.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
)

NAME = "Host Header Injection"
CATEGORY = "PT"
OWASP = "A03: Injection"
TIMEOUT = 10
EVIL_HOST = "vapt-evil.example"


def run(session, url: str) -> dict:
    # Keep the real connection, but lie about Host + X-Forwarded-Host.
    headers = {"Host": EVIL_HOST, "X-Forwarded-Host": EVIL_HOST}
    resp, err = fetch(session, url, headers=headers,
                      allow_redirects=False, timeout=TIMEOUT)
    if err or resp is None:
        return result("host_header", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not test Host header handling -- {err or 'no response'}.")

    location = resp.headers.get("Location", "")
    body = resp.text or ""

    # Reflected into a redirect target -> classic reset/cache poisoning vector.
    if EVIL_HOST in urlparse(location).netloc.lower():
        return result("host_header", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                      "Host header injection: spoofed host reflected in the redirect target.",
                      [f"Sent Host: {EVIL_HOST}", f"Response {resp.status_code} -> Location: {location}",
                       "Can enable password-reset poisoning / cache poisoning."])

    # Reflected into an absolute link/script in the page body.
    if f"//{EVIL_HOST}" in body or f"http://{EVIL_HOST}" in body or f"https://{EVIL_HOST}" in body:
        return result("host_header", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                      "Host header injection: spoofed host reflected into page URLs.",
                      [f"Sent Host: {EVIL_HOST}",
                       "The marker host appears in absolute URLs in the response body."])

    return result("host_header", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  "Spoofed Host header was not reflected -- not vulnerable.",
                  [f"Sent Host: {EVIL_HOST}; it did not appear in redirects or page URLs."])
