"""
outdated_lib_check.py -- parses page source for old jQuery / Bootstrap version
strings.

Front-end libraries with known-vulnerable versions are a common real-world
finding (e.g. jQuery < 3.5 has XSS issues, Bootstrap < 4.3.1 / < 5 has XSS in
tooltips/popovers). We look at inline markers and script src URLs, pull out the
version numbers we can find, and compare them against a minimum "safe" version.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
)

NAME = "Outdated JS Libraries"
CATEGORY = "VA"

# Minimum versions we treat as "safe enough" for this educational check.
SAFE_MINIMUMS = {
    "jquery": (3, 5, 0),
    "bootstrap": (4, 3, 1),
}

# Regexes to spot a library + version in script URLs or inline comments.
PATTERNS = {
    "jquery": re.compile(r"jquery[-./]?v?(\d+)\.(\d+)\.(\d+)", re.I),
    "bootstrap": re.compile(r"bootstrap[-./]?v?(\d+)\.(\d+)\.(\d+)", re.I),
}


def _to_tuple(m: re.Match) -> tuple:
    return tuple(int(g) for g in m.groups())


def _ver_str(t: tuple) -> str:
    return ".".join(str(x) for x in t)


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result(
            "outdated_lib", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
            f"Could not fetch page source -- {err}.",
        )

    html = resp.text or ""
    soup = BeautifulSoup(html, "html.parser")

    # Collect candidate strings: all <script src> values plus the raw HTML so we
    # also catch inline version comments like "/*! jQuery v3.3.1 */".
    haystacks = [s.get("src", "") for s in soup.find_all("script")]
    haystacks.append(html)

    outdated = []   # (lib, found_version, safe_min)
    detected = []   # (lib, found_version)

    for lib, pattern in PATTERNS.items():
        best = None
        for text in haystacks:
            if not text:
                continue
            m = pattern.search(text)
            if m:
                ver = _to_tuple(m)
                # keep the highest version we see for this lib
                if best is None or ver > best:
                    best = ver
        if best is not None:
            detected.append((lib, best))
            if best < SAFE_MINIMUMS[lib]:
                outdated.append((lib, best, SAFE_MINIMUMS[lib]))

    if not detected:
        return result(
            "outdated_lib", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
            "No jQuery/Bootstrap version strings detected in the page source.",
            ["Nothing to flag -- either not used or versions not exposed."],
        )

    evidence = [f"Detected {lib} v{_ver_str(v)}" for lib, v in detected]

    if outdated:
        for lib, found, safe in outdated:
            evidence.append(
                f"OUTDATED: {lib} v{_ver_str(found)} < safe minimum v{_ver_str(safe)}"
            )
        libs = ", ".join(f"{lib} {_ver_str(v)}" for lib, v, _ in outdated)
        return result(
            "outdated_lib", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
            f"Outdated front-end library detected: {libs}.",
            evidence,
        )

    return result(
        "outdated_lib", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
        "Detected libraries are at or above the safe minimum version.",
        evidence,
    )
