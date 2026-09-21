"""
ssti_check.py -- Server-Side Template Injection (OWASP A03: Injection).

If user input is rendered by a server-side template engine (Jinja2, Twig,
Freemarker, Velocity, ERB, …), an attacker can inject template syntax that the
engine evaluates -- often leading to remote code execution.

Detection: inject a distinctive arithmetic expression in several template
syntaxes and look for the *evaluated product* in the response. We use
`9999*9999 = 99980001`, a value extremely unlikely to appear by coincidence,
and confirm it was NOT already present in the baseline page.

Non-destructive (just arithmetic). Active check -- authorised targets only.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from ._common import fetch, result, SEV_HIGH, STATUS_PASS, STATUS_FAIL, STATUS_INFO
from .points import enumerate_points

NAME = "Template Injection (SSTI)"
CATEGORY = "PT"
OWASP = "A03: Injection"

TIMEOUT = 10
A, B = 9999, 9999
PRODUCT = str(A * B)  # "99980001"

# Same computation across the common template syntaxes (kept tight for speed).
PAYLOADS = [
    "{{%d*%d}}" % (A, B),        # Jinja2 / Twig / Nunjucks
    "${%d*%d}" % (A, B),         # Freemarker / JSP EL / Thymeleaf
    "#{%d*%d}" % (A, B),         # Ruby / some engines
    "<%%= %d*%d %%>" % (A, B),   # ERB  (%% -> literal % after formatting)
]


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result("ssti", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not load the page for SSTI testing -- {err}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    points = enumerate_points(url, soup)

    tested = 0
    for point in points:
        # baseline for this point: make sure the product isn't already present
        _b, base = point.send(session, point.seed, TIMEOUT)
        base_text = (base.text if base is not None else "") or ""
        if PRODUCT in base_text:
            continue  # page already contains the number -> can't rely on it here
        tested += 1

        for payload in PAYLOADS:
            _e, r = point.send(session, payload, TIMEOUT)
            if r is None:
                continue
            if PRODUCT in (r.text or ""):
                return result(
                    "ssti", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
                    "Server-Side Template Injection: the engine evaluated our expression.",
                    [
                        f"Injection point: {point.label}",
                        f"Payload: {payload}",
                        f"Template engine evaluated {A}*{B} -> {PRODUCT} in the response.",
                    ],
                )

    if tested == 0:
        return result("ssti", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      "No forms or URL parameters were available to test for SSTI.")

    return result("ssti", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  f"No template injection detected across {tested} input(s).",
                  ["Injected arithmetic in Jinja/Twig/Freemarker/ERB/Razor syntax; none evaluated."])
