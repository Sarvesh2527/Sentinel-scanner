"""
csrf_check.py -- Missing CSRF protection (OWASP A01).

State-changing forms (method POST) should carry an unpredictable anti-CSRF token
so another site can't submit them on a logged-in user's behalf. We look at each
POST form for a hidden token field; forms without one are flagged for review.
This is a heuristic (some apps use header-based or SameSite-cookie protection),
so it is reported as a warning, not a hard failure.
"""

from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_WARN, STATUS_INFO,
)

NAME = "CSRF Protection"
CATEGORY = "VA"
OWASP = "A01: Broken Access Control"
TIMEOUT = 10

# Hidden-field names that usually hold an anti-CSRF token.
TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity", "nonce", "_wpnonce",
               "__requestverificationtoken")


def _has_token(form) -> bool:
    for inp in form.find_all("input"):
        name = (inp.get("name") or "").lower()
        itype = (inp.get("type") or "text").lower()
        if any(h in name for h in TOKEN_HINTS):
            return True
        # long random hidden values are often unnamed tokens too
        if itype == "hidden" and len(inp.get("value") or "") >= 16 and \
           any(h in name for h in ("token", "csrf", "auth")):
            return True
    return False


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("csrf", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      f"Could not fetch the page -- {err or 'no response'}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    post_forms = [f for f in soup.find_all("form")
                  if (f.get("method") or "get").lower() == "post"]

    if not post_forms:
        return result("csrf", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      "No state-changing (POST) forms found to assess for CSRF.")

    unprotected = []
    for i, form in enumerate(post_forms, 1):
        if not _has_token(form):
            action = urljoin(resp.url, form.get("action") or resp.url)
            unprotected.append(f"POST form #{i} -> {action} (no anti-CSRF token field)")

    if unprotected:
        return result("csrf", NAME, CATEGORY, STATUS_WARN, SEV_MEDIUM,
                      f"{len(unprotected)}/{len(post_forms)} POST form(s) have no visible CSRF token.",
                      unprotected + ["Verify CSRF tokens or SameSite-cookie protection is in place."])

    return result("csrf", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  f"All {len(post_forms)} POST form(s) include an anti-CSRF token field.",
                  ["Each state-changing form carries a token."])
