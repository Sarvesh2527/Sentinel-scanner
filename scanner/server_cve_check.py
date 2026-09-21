"""
server_cve_check.py -- known-CVE detection from version banners
(OWASP A06: Vulnerable and Outdated Components).

Servers and frameworks often advertise their exact version in response headers
(`Server`, `X-Powered-By`, `X-AspNet-Version`) or in the page (`<meta generator>`,
library version strings). When that version is one with a *published, patched*
CVE, the banner is a give-away that the component is unpatched. We fingerprint
the version and match it against a curated CVE table.

This is passive (read-only) fingerprinting -- we never exploit anything. It's the
"the fix exists, but this host still shows the vulnerable version" check.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_HIGH, SEV_MEDIUM, SEV_LOW,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
)

NAME = "Known CVEs / Outdated Components"
CATEGORY = "VA"
OWASP = "A06: Vulnerable & Outdated Components"

TIMEOUT = 10


def _ver(*parts):
    return tuple(int(p) for p in parts)


# Curated CVE table. Each entry: a regex that captures a version, and a list of
# (test, cve, severity, description). `test` receives the version tuple.
# Kept deliberately small and well-known so findings are defensible in a viva.
CVE_RULES = [
    {
        "name": "Apache httpd",
        "regex": re.compile(r"apache/(\d+)\.(\d+)\.(\d+)", re.I),
        "vulns": [
            (lambda v: v == _ver(2, 4, 49), "CVE-2021-41773", SEV_HIGH,
             "Path traversal & RCE in Apache 2.4.49"),
            (lambda v: v == _ver(2, 4, 50), "CVE-2021-42013", SEV_HIGH,
             "Path traversal & RCE in Apache 2.4.50 (incomplete 41773 fix)"),
            (lambda v: v < _ver(2, 4, 49), "CVE-various", SEV_MEDIUM,
             "Apache < 2.4.49 has multiple patched CVEs; upgrade recommended"),
        ],
    },
    {
        "name": "nginx",
        "regex": re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)", re.I),
        "vulns": [
            (lambda v: _ver(1, 3, 9) <= v <= _ver(1, 4, 0), "CVE-2013-2028", SEV_HIGH,
             "Chunked transfer stack overflow in nginx 1.3.9–1.4.0"),
            (lambda v: v < _ver(1, 20, 1), "CVE-various", SEV_LOW,
             "nginx < 1.20.1 predates several patched advisories"),
        ],
    },
    {
        "name": "PHP",
        "regex": re.compile(r"php/(\d+)\.(\d+)\.(\d+)", re.I),
        "vulns": [
            (lambda v: v < _ver(7, 0, 0), "EOL/CVE-various", SEV_HIGH,
             "PHP 5.x is end-of-life with many unpatched CVEs"),
            (lambda v: _ver(7, 0, 0) <= v < _ver(7, 4, 0), "EOL", SEV_MEDIUM,
             "PHP < 7.4 is end-of-life (no security fixes)"),
        ],
    },
    {
        "name": "OpenSSL",
        "regex": re.compile(r"openssl/(\d+)\.(\d+)\.(\d+)", re.I),
        "vulns": [
            (lambda v: v <= _ver(1, 0, 1), "CVE-2014-0160", SEV_HIGH,
             "Possible Heartbleed range (OpenSSL 1.0.1–1.0.1f)"),
        ],
    },
    {
        "name": "jQuery",
        "regex": re.compile(r"jquery[-/](\d+)\.(\d+)\.(\d+)", re.I),
        "vulns": [
            (lambda v: v < _ver(3, 5, 0), "CVE-2020-11022/11023", SEV_MEDIUM,
             "jQuery < 3.5.0 XSS in HTML manipulation"),
        ],
    },
    {
        "name": "Bootstrap",
        "regex": re.compile(r"bootstrap[-/](\d+)\.(\d+)\.(\d+)", re.I),
        "vulns": [
            (lambda v: _ver(4, 0, 0) <= v < _ver(4, 3, 1), "CVE-2019-8331", SEV_MEDIUM,
             "Bootstrap 4.x < 4.3.1 XSS in tooltip/popover"),
            (lambda v: v < _ver(3, 4, 1), "CVE-2018-14041", SEV_MEDIUM,
             "Bootstrap 3.x < 3.4.1 XSS"),
        ],
    },
]


def _scan_text(text, findings, seen):
    for rule in CVE_RULES:
        m = rule["regex"].search(text or "")
        if not m:
            continue
        version = _ver(*m.groups())
        vstr = ".".join(str(x) for x in version)
        for test, cve, sev, desc in rule["vulns"]:
            try:
                hit = test(version)
            except Exception:
                hit = False
            key = (rule["name"], vstr, cve)
            if hit and key not in seen:
                seen.add(key)
                findings.append((sev, f"{rule['name']} {vstr} -> {cve}: {desc}"))
                break  # one (worst) CVE per detected component is enough


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("server_cve", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not fingerprint the server -- {err or 'no response'}.")

    findings, seen = [], set()
    disclosures = []

    # 1) Version-bearing headers
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
              "X-Generator"):
        val = resp.headers.get(h)
        if val:
            _scan_text(val, findings, seen)
            if re.search(r"\d+\.\d+", val):
                disclosures.append(f"{h}: {val}")

    # 2) Page source (meta generator + library version strings)
    body = resp.text or ""
    soup = BeautifulSoup(body, "html.parser")
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        _scan_text(gen["content"], findings, seen)
        disclosures.append(f"<meta generator>: {gen['content']}")
    _scan_text(body, findings, seen)

    if findings:
        # highest severity present drives the card severity
        sev = SEV_HIGH if any(s == SEV_HIGH for s, _ in findings) else SEV_MEDIUM
        return result("server_cve", NAME, CATEGORY, STATUS_FAIL, sev,
                      f"{len(findings)} component(s) match a known CVE / EOL advisory.",
                      [msg for _s, msg in findings] + disclosures)

    if disclosures:
        return result("server_cve", NAME, CATEGORY, STATUS_WARN, SEV_LOW,
                      "Version banners are exposed (information disclosure, no known CVE matched).",
                      disclosures + ["Hide version numbers from Server / X-Powered-By headers."])

    return result("server_cve", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  "No known-vulnerable component versions were advertised.",
                  ["No version-bearing banners matched the CVE table."])
