"""
cors_check.py -- CORS misconfiguration (OWASP A05: Security Misconfiguration).

A server that reflects an arbitrary `Origin` into `Access-Control-Allow-Origin`
-- especially together with `Access-Control-Allow-Credentials: true` -- lets any
website read authenticated responses on the victim's behalf. We send a request
with a foreign Origin and inspect the CORS response headers.
"""

from __future__ import annotations

from ._common import (
    fetch, result, SEV_MEDIUM, SEV_LOW,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
)

NAME = "CORS Misconfiguration"
CATEGORY = "VA"
OWASP = "A05: Security Misconfiguration"

TIMEOUT = 8
EVIL_ORIGIN = "https://vapt-evil.example"


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, headers={"Origin": EVIL_ORIGIN}, timeout=TIMEOUT)
    if err or resp is None:
        return result("cors", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not test CORS -- {err or 'no response'}.")

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if not acao:
        return result("cors", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                      "No cross-origin sharing headers returned for a foreign Origin.",
                      ["Server did not send Access-Control-Allow-Origin for our test Origin."])

    # Worst case: reflects the attacker origin AND allows credentials.
    if acao == EVIL_ORIGIN and acac == "true":
        return result("cors", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                      "CORS misconfiguration: reflects any Origin with credentials allowed.",
                      [f"Access-Control-Allow-Origin: {acao}",
                       "Access-Control-Allow-Credentials: true",
                       "Any site can read authenticated responses from this server."])

    if acao == EVIL_ORIGIN:
        return result("cors", NAME, CATEGORY, STATUS_FAIL, SEV_LOW,
                      "CORS reflects an arbitrary Origin (no credentials).",
                      [f"Access-Control-Allow-Origin: {acao}",
                       "The server echoes any Origin -- review the allow-list."])

    if acao == "*" and acac == "true":
        return result("cors", NAME, CATEGORY, STATUS_WARN, SEV_MEDIUM,
                      "CORS allows '*' together with credentials (browsers block, but misconfigured).",
                      ["Access-Control-Allow-Origin: *",
                       "Access-Control-Allow-Credentials: true"])

    if acao == "*":
        return result("cors", NAME, CATEGORY, STATUS_WARN, SEV_LOW,
                      "CORS is wide open (Access-Control-Allow-Origin: *).",
                      ["Fine for public data; risky if the endpoint returns anything private."])

    return result("cors", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  "CORS did not reflect our foreign Origin.",
                  [f"Access-Control-Allow-Origin: {acao}"])
