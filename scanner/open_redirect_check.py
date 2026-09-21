"""
open_redirect_check.py -- Open Redirect (OWASP A01) and SSRF surface (A10).

If a parameter controls where the app redirects (`?next=`, `?url=`, `?return=`),
an attacker can send victims to a malicious site through a trusted domain, or --
if the value is fetched server-side -- reach internal services (SSRF).

Detection: inject a benign external marker URL into redirect-style parameters
and check whether the response's `Location` header (or a meta/JS redirect in the
body) sends the user to our marker host. We do NOT follow the redirect.
"""

from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
    query_pairs, with_query_param,
)

NAME = "Open Redirect"
CATEGORY = "PT"
OWASP = "A01: Broken Access Control"

TIMEOUT = 10
MARKER_HOST = "vapt-evil.example"
MARKER = f"https://{MARKER_HOST}/"

# Parameter names that commonly carry a redirect/next/url target.
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "next", "return",
    "returnurl", "return_url", "returnto", "dest", "destination", "continue",
    "goto", "out", "target", "redir", "link", "u", "r", "callback", "forward",
]


def _redirects_to_marker(resp) -> bool:
    """True if the response sends the browser to our marker host."""
    if resp is None:
        return False
    location = resp.headers.get("Location", "")
    if 300 <= resp.status_code < 400 and MARKER_HOST in urlparse(location).netloc.lower():
        return True
    return _body_redirects(resp.text or "")


def _combined_guess_url(url):
    """One URL with every redirect param name set to the marker, for a single
    probe on a bare URL instead of one request per name."""
    if query_pairs(url):
        return None
    out = url
    for n in REDIRECT_PARAMS:
        out = with_query_param(out, n, MARKER)
    return out


def _body_redirects(text: str) -> bool:
    low = (text or "").lower()
    return (f'url={MARKER.lower()}' in low.replace(" ", "")) or \
           (f'location.href="{MARKER.lower()}"' in low.replace(" ", "").replace("'", '"')) or \
           (MARKER_HOST in low and ("http-equiv=\"refresh\"" in low or "window.location" in low))


def _hit(name, probe_url):
    return result(
        "open_redirect", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
        f"Open redirect: parameter '{name}' redirects to an attacker-controlled URL.",
        [
            f"Injection point: URL parameter '{name}'",
            f"Request: {probe_url}",
            "The response sends the browser to the external marker host.",
            "Also an SSRF surface if the value is fetched server-side.",
        ],
    )


def run(session, url: str) -> dict:
    existing = [n for n, _ in query_pairs(url)]
    tested = 0

    # ---- 1) Existing redirect-style parameters ---------------------------
    for name in [n for n in existing if n.lower() in REDIRECT_PARAMS]:
        probe = with_query_param(url, name, MARKER)
        resp, err = fetch(session, probe, method="get",
                          allow_redirects=False, timeout=TIMEOUT)
        if err or resp is None:
            continue
        tested += 1
        if _redirects_to_marker(resp):
            return _hit(name, probe)

    # ---- 2) Bare URL: one combined probe, fan out only on a hit ----------
    guess_url = _combined_guess_url(url)
    if guess_url:
        resp, err = fetch(session, guess_url, method="get",
                          allow_redirects=False, timeout=TIMEOUT)
        if not err and resp is not None:
            tested += 1
            if _redirects_to_marker(resp):
                for name in REDIRECT_PARAMS:
                    one = with_query_param(url, name, MARKER)
                    r, e = fetch(session, one, method="get",
                                 allow_redirects=False, timeout=TIMEOUT)
                    if not e and _redirects_to_marker(r):
                        return _hit(name, one)
                return _hit("a redirect parameter", guess_url)

    if tested == 0:
        return result("open_redirect", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      "No redirect-style URL parameters were available to test.")

    return result("open_redirect", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  f"No open redirect detected across {tested} probe(s).",
                  ["Injected an external marker URL into redirect-style parameters."])
