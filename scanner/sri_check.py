"""
sri_check.py -- Missing Subresource Integrity (OWASP A08).

When a page loads a script or stylesheet from a third-party origin (a CDN)
without a Subresource Integrity (`integrity="sha384-…"`) attribute, a compromise
of that CDN silently runs attacker code on the site. SRI pins the expected hash.
We flag cross-origin scripts/styles that have no integrity attribute.
"""

from __future__ import annotations

from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_WARN, STATUS_INFO,
)

NAME = "Subresource Integrity"
CATEGORY = "VA"
OWASP = "A08: Software & Data Integrity Failures"
TIMEOUT = 10


def _cross_origin(resource_url, page_host):
    host = urlparse(resource_url).netloc.lower()
    return bool(host) and host != page_host


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("sri", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not fetch the page -- {err or 'no response'}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    page_host = urlparse(resp.url).netloc.lower()
    missing, external_total = [], 0

    for s in soup.find_all("script", src=True):
        abs_url = urljoin(resp.url, s["src"])
        if _cross_origin(abs_url, page_host):
            external_total += 1
            if not s.get("integrity"):
                missing.append(f"<script> {abs_url[:90]}")

    for l in soup.find_all("link", href=True):
        rels = [r.lower() for r in (l.get("rel") or [])]
        if "stylesheet" not in rels:
            continue
        abs_url = urljoin(resp.url, l["href"])
        if _cross_origin(abs_url, page_host):
            external_total += 1
            if not l.get("integrity"):
                missing.append(f"<link> {abs_url[:90]}")

    if external_total == 0:
        return result("sri", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                      "No third-party scripts/styles loaded -- SRI not needed.",
                      ["All resources are same-origin."])
    if missing:
        return result("sri", NAME, CATEGORY, STATUS_WARN, SEV_MEDIUM,
                      f"{len(missing)}/{external_total} cross-origin resource(s) lack Subresource Integrity.",
                      missing[:10] + ["Add integrity=\"sha384-…\" + crossorigin to third-party tags."])

    return result("sri", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  f"All {external_total} cross-origin resource(s) use Subresource Integrity.",
                  ["Every third-party script/style is hash-pinned."])
