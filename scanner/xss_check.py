"""
xss_check.py -- reflected XSS (OWASP A03: Injection).

Submits a unique, benign marker payload into every individual input -- each form
field (including search bars), each URL query parameter, and, for a bare URL, a
set of common search-parameter names -- and reports if the raw, un-escaped
payload comes back in the response (proving the sink is unsafe).

Testing each input on its own (not all fields at once) pinpoints exactly which
field or parameter is vulnerable.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_HIGH,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
    query_pairs, with_query_param, combined_guess_url, COMMON_PARAMS,
)
from .points import enumerate_points, has_search_input

NAME = "Reflected XSS"
CATEGORY = "PT"
OWASP = "A03: Injection"
TIMEOUT = 10

MARKER = "vapt7xss9probe"
PAYLOAD = f"<{MARKER}>"


def _hit(where, url):
    return result(
        "xss", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
        f"Reflected XSS: a {where} echoed our payload back unescaped.",
        [
            f"Vulnerable URL/point: {url}",
            f"Injection point: {where}",
            f"Payload reflected verbatim: {PAYLOAD}",
        ],
    )


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result("xss", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not load the page to test for XSS -- {err}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    tested = 0

    # ---- 1) Every individual form field and URL parameter ----------------
    for point in enumerate_points(resp.url, soup):
        _e, r = point.send(session, PAYLOAD, TIMEOUT)
        if r is None:
            continue
        tested += 1
        if PAYLOAD in (r.text or ""):
            return _hit(point.label, resp.url)

    # ---- 2) Search-bar guess on a bare URL (one combined probe) ----------
    guess_url = combined_guess_url(resp.url, PAYLOAD, force=has_search_input(soup))
    if guess_url:
        r, e = fetch(session, guess_url, method="GET")
        if not e and r is not None:
            tested += 1
            if PAYLOAD in (r.text or ""):
                for name in COMMON_PARAMS:
                    one = with_query_param(resp.url, name, PAYLOAD)
                    rr, ee = fetch(session, one, method="GET")
                    if not ee and rr is not None and PAYLOAD in (rr.text or ""):
                        return _hit(f"search parameter '{name}'", one)
                return _hit("a search parameter", guess_url)

    if tested == 0:
        return result("xss", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      "No forms or URL parameters were available to test for reflected XSS.")

    return result("xss", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  f"No reflected XSS found -- payload was escaped across {tested} input(s).",
                  ["Tested each form field, search bar and URL parameter individually."])
