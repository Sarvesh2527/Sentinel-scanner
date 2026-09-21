"""
command_injection_check.py -- OS command injection (OWASP A03: Injection).

If user input is passed into a shell command, an attacker can run arbitrary OS
commands. Like blind SQLi, the reliable, output-free way to detect it is
*time-based*: inject a shell `sleep` and see whether the response is delayed,
then confirm with a longer sleep that must scale. Covers both Unix (`sleep`) and
Windows (`ping -n` / `timeout`) and several shell metacharacters.

Non-destructive: the only command injected is a sleep/ping delay. Nothing reads,
writes or deletes anything. Active check -- authorised targets only.
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from ._common import fetch, result, SEV_HIGH, STATUS_PASS, STATUS_FAIL, STATUS_INFO
from .points import enumerate_points, time_based_probe

NAME = "Command Injection"
CATEGORY = "PT"
OWASP = "A03: Injection"

BASE_DELAY = 3
CONFIRM_DELAY = 6
TIMEOUT = 15
MAX_POINTS = 4   # time-based probes are expensive -- cap the inputs tested

# Shell payload templates. {S} = sleep seconds. A tight, high-signal set keeps
# the request count down; different metacharacters cover common contexts.
SHELL_PAYLOADS = {
    "Unix shell": [
        "; sleep {S}",
        "| sleep {S}",
        "$(sleep {S})",
        "`sleep {S}`",
    ],
    "Windows shell": [
        "& ping -n {S} 127.0.0.1",
    ],
}


def _value(seed, payload):
    # command injection is appended to whatever the field already contained
    return f"{seed}{payload}"


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result("cmd_injection", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not load the page for command-injection testing -- {err}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    points = enumerate_points(url, soup, limit=MAX_POINTS)

    tested = 0
    for point in points:
        tested += 1
        try:
            hit = time_based_probe(session, point, SHELL_PAYLOADS,
                                   BASE_DELAY, CONFIRM_DELAY, TIMEOUT,
                                   value_builder=_value)
        except Exception:
            hit = None
        if hit:
            family, tmpl = hit
            return result(
                "cmd_injection", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
                f"Time-based OS command injection confirmed ({family}).",
                [
                    f"Injection point: {point.label}",
                    f"Technique: time-based (delay scaled {BASE_DELAY}s -> {CONFIRM_DELAY}s)",
                    f"Payload shape: {point.seed}{tmpl.format(S=BASE_DELAY)}",
                    "Detected purely by response delay -- no command output needed.",
                ],
            )

    if tested == 0:
        return result("cmd_injection", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      "No forms or URL parameters were available to test for command injection.")

    return result("cmd_injection", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  f"No OS command injection detected across {tested} input(s).",
                  ["Sent time-based shell probes (Unix & Windows); no scaling delay observed."])
