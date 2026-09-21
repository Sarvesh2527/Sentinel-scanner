"""
http_methods_check.py -- Dangerous HTTP methods (OWASP A05).

Asks the server which HTTP methods it allows (OPTIONS) and actively checks for
TRACE (which enables Cross-Site Tracing / XST). Write methods (PUT/DELETE/PATCH)
left enabled on a normal endpoint are worth flagging; TRACE is a concrete issue.
"""

from __future__ import annotations

from ._common import (
    fetch, result, SEV_MEDIUM, SEV_LOW,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
)

NAME = "HTTP Methods"
CATEGORY = "VA"
OWASP = "A05: Security Misconfiguration"
TIMEOUT = 8

RISKY = {"PUT", "DELETE", "PATCH", "CONNECT"}


def run(session, url: str) -> dict:
    allow = ""
    resp, err = fetch(session, url, method="OPTIONS", timeout=TIMEOUT)
    if resp is not None:
        allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}

    # Actively test TRACE for Cross-Site Tracing (XST).
    trace_enabled = False
    tr, terr = fetch(session, url, method="TRACE", timeout=TIMEOUT)
    if tr is not None and tr.status_code == 200 and "TRACE" in (tr.text or "").upper()[:200]:
        trace_enabled = True

    risky = methods & RISKY
    evidence = []
    if allow:
        evidence.append(f"Allow: {allow}")

    if trace_enabled:
        return result("http_methods", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                      "TRACE method is enabled -- vulnerable to Cross-Site Tracing (XST).",
                      evidence + ["Server echoed the TRACE request; disable the TRACE method."])
    if risky:
        return result("http_methods", NAME, CATEGORY, STATUS_WARN, SEV_LOW,
                      f"Potentially dangerous methods enabled: {', '.join(sorted(risky))}.",
                      evidence + ["Confirm these write methods are intended and access-controlled."])
    if not methods and (err or resp is None):
        return result("http_methods", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      "Server did not answer OPTIONS; could not enumerate methods.")

    return result("http_methods", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  "No dangerous HTTP methods (TRACE / PUT / DELETE) are enabled.",
                  evidence or ["Only safe methods appear to be allowed."])
