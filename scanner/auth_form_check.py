"""
auth_form_check.py -- Login / authentication form security (OWASP A07).

Checks any form that contains a password field for two common weaknesses:
  * credentials submitted over plain HTTP (or to an http:// action) -- passwords
    travel in cleartext;
  * password fields that allow autocomplete, so browsers may cache credentials
    on shared machines.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_HIGH, SEV_LOW,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
)

NAME = "Login Form Security"
CATEGORY = "VA"
OWASP = "A07: Identification & Authentication Failures"
TIMEOUT = 10

SAFE_AUTOCOMPLETE = ("off", "new-password", "current-password")


def run(session, url: str) -> dict:
    resp, err = fetch(session, url, timeout=TIMEOUT)
    if err or resp is None:
        return result("auth_form", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not fetch the page -- {err or 'no response'}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    page_scheme = urlparse(resp.url).scheme

    pw_forms = [f for f in soup.find_all("form")
                if f.find("input", attrs={"type": "password"})]
    if not pw_forms:
        return result("auth_form", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      "No login / password forms found to assess.")

    cleartext, autocomplete = [], []
    for i, form in enumerate(pw_forms, 1):
        action = urljoin(resp.url, form.get("action") or resp.url)
        # credentials over http (page or form action)
        if page_scheme != "https" or urlparse(action).scheme == "http":
            cleartext.append(f"Login form #{i} submits over HTTP -> {action}")
        # password autocomplete
        for pw in form.find_all("input", attrs={"type": "password"}):
            ac = (pw.get("autocomplete") or form.get("autocomplete") or "").lower()
            if ac not in SAFE_AUTOCOMPLETE:
                autocomplete.append(f"Login form #{i}: password field allows autocomplete")
                break

    if cleartext:
        return result("auth_form", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
                      "Login credentials are submitted over plain HTTP (cleartext).",
                      cleartext + autocomplete + ["Serve and submit login forms only over HTTPS."])
    if autocomplete:
        return result("auth_form", NAME, CATEGORY, STATUS_WARN, SEV_LOW,
                      f"{len(autocomplete)} login form(s) allow password autocomplete.",
                      autocomplete + ["Set autocomplete=\"new-password\"/\"current-password\" where appropriate."])

    return result("auth_form", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  f"Login form(s) submit over HTTPS with sane autocomplete settings.",
                  [f"Assessed {len(pw_forms)} password form(s)."])
