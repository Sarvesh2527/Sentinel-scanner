"""
sqli_check.py -- error-based SQL injection (OWASP A03: Injection).

Submits breaker payloads into every individual input -- each form field
(including search bars), each URL query parameter, and (for a bare URL) common
search-parameter names -- and looks for raw database error signatures. Seeing a
DB error means our input reached a SQL query unsanitised.

Blind / time-based / boolean SQLi (no error shown) is handled by
`advanced_sqli_check.py`.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_HIGH,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
    query_pairs, with_query_param, combined_guess_url, COMMON_PARAMS,
)
from .points import enumerate_points, has_search_input

NAME = "SQL Injection"
CATEGORY = "PT"
OWASP = "A03: Injection"
TIMEOUT = 10

PAYLOADS = ["'", "\"", "')", "1'--"]

ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"psql:.*error",
    r"sqlite3?::",
    r"sqlite_error",
    r"sqlstate\[",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"supplied argument is not a valid mysql",
]
ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.I)


def _hit(where, payload, match):
    return result(
        "sqli", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
        f"SQL injection: a database error surfaced from {where}.",
        [
            f"Injection point: {where}",
            f"Trigger payload: {payload}",
            f"DB error signature matched: '{match.group(0)[:60]}'",
        ],
    )


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result("sqli", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not load the page to test for SQL injection -- {err}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    tested = 0

    # ---- 1) Every individual form field and URL parameter ----------------
    for point in enumerate_points(resp.url, soup):
        for payload in PAYLOADS:
            _e, r = point.send(session, payload, TIMEOUT)
            if r is None:
                continue
            tested += 1
            m = ERROR_RE.search(r.text or "")
            if m:
                return _hit(point.label, payload, m)

    # ---- 2) Search-bar guess on a bare URL (one combined probe) ----------
    guess_url = combined_guess_url(url, PAYLOADS[0], force=has_search_input(soup))
    if guess_url:
        r, e = fetch(session, guess_url, method="GET")
        if not e and r is not None:
            tested += 1
            m = ERROR_RE.search(r.text or "")
            if m:
                for name in COMMON_PARAMS:
                    one = with_query_param(url, name, PAYLOADS[0])
                    rr, ee = fetch(session, one, method="GET")
                    if not ee and rr is not None:
                        mm = ERROR_RE.search(rr.text or "")
                        if mm:
                            return _hit(f"search parameter '{name}'", PAYLOADS[0], mm)
                return _hit("a search parameter", PAYLOADS[0], m)

    if tested == 0:
        return result("sqli", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      "No forms or URL parameters were available to test for SQL injection.")

    return result("sqli", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  f"No SQL error signatures triggered across {tested} test(s).",
                  ["Tested each form field, search bar and URL parameter individually."])
