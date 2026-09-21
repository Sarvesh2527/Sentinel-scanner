"""
https_check.py -- verifies the target uses HTTPS instead of HTTP.

We check two things:
  1. Was the final URL (after redirects) served over HTTPS?
  2. If the user gave an http:// URL, does the site upgrade them to https://?

A site that stays on plain HTTP exposes all traffic to eavesdropping and
tampering, so this is a HIGH severity failure when it fails.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ._common import (
    fetch, result, SEV_HIGH,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
)

NAME = "HTTPS Usage"
CATEGORY = "VA"


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result(
            "https", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
            f"Could not verify HTTPS -- {err}.",
        )

    final_url = resp.url
    scheme = urlparse(final_url).scheme

    if scheme == "https":
        evidence = [f"Final URL: {final_url}"]
        # Note if the user typed http and the server upgraded them.
        if url.startswith("http://"):
            evidence.append("Server redirected the http:// request to https://.")
        return result(
            "https", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
            "The site is served over HTTPS (encrypted).",
            evidence,
        )

    return result(
        "https", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
        "The site is served over plain HTTP -- traffic is not encrypted.",
        [f"Final URL: {final_url}"],
    )
