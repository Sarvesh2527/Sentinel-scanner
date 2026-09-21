"""
idor_check.py -- scans URLs and forms for object-reference patterns
(id=, user_id=, order_id=, etc.).

This is a PATTERN detector, not an exploit. Insecure Direct Object Reference
(IDOR) happens when an app exposes a raw object id and doesn't check that the
current user is allowed to see it. We can't safely confirm the access-control
flaw without authenticating as two users, so we flag the *surface*: places
where a numeric/reference id is passed around and would be worth manual testing.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_WARN, STATUS_INFO,
)

NAME = "IDOR Pattern Detection"
CATEGORY = "VA"

# Parameter names that commonly reference an object by id.
IDOR_PARAM_RE = re.compile(
    r"^(id|.*_id|.*id|uid|pid|oid|no|num|number|ref|order|account|user|"
    r"customer|invoice|file|doc|document|profile)$",
    re.I,
)

# A value that looks like a raw sequential id (all digits) is the classic case.
NUMERIC_RE = re.compile(r"^\d+$")


def _flag_params(source: str, query: str):
    """Return list of 'source: name=value' strings for id-like params."""
    hits = []
    for name, values in parse_qs(query, keep_blank_values=True).items():
        if IDOR_PARAM_RE.match(name):
            val = values[0] if values else ""
            numeric = " (numeric)" if NUMERIC_RE.match(val or "") else ""
            hits.append(f"{source}: {name}={val}{numeric}")
    return hits


def run(session, url: str) -> dict:
    findings = []

    # 1) The target URL's own query string.
    findings += _flag_params("URL", urlparse(url).query)

    # 2) Links and form actions in the page body.
    resp, err = fetch(session, url)
    if err:
        # We can still report on the URL itself even if the page won't load.
        if findings:
            return result(
                "idor", NAME, CATEGORY, STATUS_WARN, SEV_MEDIUM,
                "Object-reference parameters found in the URL (worth manual IDOR testing).",
                findings,
            )
        return result(
            "idor", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
            f"Could not fetch page to scan for IDOR patterns -- {err}.",
        )

    soup = BeautifulSoup(resp.text or "", "html.parser")

    for a in soup.find_all("a", href=True):
        findings += _flag_params("link", urlparse(a["href"]).query)

    for form in soup.find_all("form"):
        # id-like hidden/visible inputs inside forms
        for inp in form.find_all(["input", "select"]):
            name = inp.get("name", "")
            if name and IDOR_PARAM_RE.match(name):
                val = inp.get("value", "")
                findings.append(f"form field: {name}={val}")

    # De-duplicate while preserving order.
    seen = set()
    unique = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            unique.append(f)

    if unique:
        return result(
            "idor", NAME, CATEGORY, STATUS_WARN, SEV_MEDIUM,
            f"Found {len(unique)} object-reference pattern(s) worth manual IDOR testing.",
            unique[:20],  # cap evidence so the card stays readable
        )

    return result(
        "idor", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
        "No obvious id-style object-reference parameters were found.",
        ["Scanned URL query, page links and form fields."],
    )
