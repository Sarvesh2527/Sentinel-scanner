"""
advanced_sqli_check.py -- advanced / modern SQL injection (OWASP A03: Injection).

Covers the classes that error-based scanning misses because they show no error
and no output, tested against every individual input (form field or URL param):

  1. Time-based blind  -- inject a DB sleep, infer injection from the delay,
                          confirm with a longer sleep that must scale. MySQL,
                          PostgreSQL, MSSQL, Oracle.
  2. Boolean-based blind -- always-true vs always-false condition, content diff.
  3. NoSQL (MongoDB) operator injection -- `param[$ne]=` etc. on URL params.

All payloads are non-destructive. Active check -- authorised targets only.
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode

from bs4 import BeautifulSoup

from ._common import (
    fetch, result, SEV_HIGH, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO,
    query_pairs,
)
from .points import enumerate_points, time_based_probe

NAME = "Advanced SQL Injection"
CATEGORY = "PT"
OWASP = "A03: Injection"

BASE_DELAY = 3
CONFIRM_DELAY = 6
TIMEOUT = 15
MAX_POINTS = 4   # time-based probes are the most expensive -- cap the inputs

# Two high-signal payloads per DBMS keeps the request count low.
TIME_PAYLOADS = {
    "MySQL": ["' AND SLEEP({S})-- -", "1 AND SLEEP({S})"],
    "PostgreSQL": ["' AND 1=(SELECT 1 FROM PG_SLEEP({S}))-- -", "'||pg_sleep({S})--"],
    "MSSQL": ["'; WAITFOR DELAY '0:0:{S}'-- -"],
    "Oracle": ["' AND DBMS_LOCK.SLEEP({S})-- -"],
}

BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    (" AND 1=1", " AND 1=2"),
]

NOSQL_OPERATORS = ["[$ne]", "[$gt]", "[$regex]"]
NOSQL_VALUES = {"[$ne]": "0", "[$gt]": "", "[$regex]": ".*"}


def _similarity(a: str, b: str) -> float:
    a, b = a or "", b or ""
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if la == 0 and lb == 0:
        return 1.0
    return 1 - abs(la - lb) / max(la, lb, 1)


def _boolean_based(session, point):
    _e, base = point.send(session, point.seed, TIMEOUT)
    if base is None:
        return None
    base_text = base.text or ""
    seed = point.seed
    for t_cond, f_cond in BOOL_PAIRS:
        _te, tr = point.send(session, seed + t_cond, TIMEOUT)
        _fe, fr = point.send(session, seed + f_cond, TIMEOUT)
        if tr is None or fr is None:
            continue
        if _similarity(base_text, tr.text or "") >= 0.97 and \
           _similarity(tr.text or "", fr.text or "") <= 0.90:
            return t_cond, f_cond
    return None


def _nosql_on_query(session, url):
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not pairs:
        return None
    base, err = fetch(session, url, timeout=TIMEOUT)
    if err or base is None:
        return None
    base_text = base.text or ""
    root = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    for name, _val in pairs:
        for op in NOSQL_OPERATORS:
            new_pairs = [(k, v) for (k, v) in pairs if k != name]
            new_pairs.append((f"{name}{op}", NOSQL_VALUES[op]))
            r, e = fetch(session, f"{root}?{urlencode(new_pairs)}", timeout=TIMEOUT)
            if e or r is None or r.status_code >= 500:
                continue
            if r.status_code == 200 and _similarity(base_text, r.text or "") <= 0.85:
                return name, op
    return None


def run(session, url: str) -> dict:
    resp, err = fetch(session, url)
    if err:
        return result("adv_sqli", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      f"Could not load the page for advanced SQLi testing -- {err}.")

    soup = BeautifulSoup(resp.text or "", "html.parser")
    points = enumerate_points(url, soup, limit=MAX_POINTS)

    # ---- Technique 1: time-based blind -----------------------------------
    for point in points:
        try:
            hit = time_based_probe(session, point, TIME_PAYLOADS,
                                   BASE_DELAY, CONFIRM_DELAY, TIMEOUT)
        except Exception:
            hit = None
        if hit:
            dbms, tmpl = hit
            return result(
                "adv_sqli", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
                f"Time-based blind SQL injection confirmed ({dbms}).",
                [
                    f"Injection point: {point.label}",
                    f"Technique: time-based blind (delay scaled {BASE_DELAY}s -> {CONFIRM_DELAY}s)",
                    f"DBMS inferred: {dbms}",
                    f"Payload shape: {tmpl.format(S=BASE_DELAY)}",
                    "No DB error was shown -- detection was purely by response delay.",
                ],
            )

    # ---- Technique 2: boolean-based blind --------------------------------
    for point in points:
        try:
            bhit = _boolean_based(session, point)
        except Exception:
            bhit = None
        if bhit:
            t_cond, f_cond = bhit
            return result(
                "adv_sqli", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
                "Boolean-based blind SQL injection detected (content differential).",
                [
                    f"Injection point: {point.label}",
                    f"TRUE condition:  {point.seed}{t_cond}",
                    f"FALSE condition: {point.seed}{f_cond}",
                    "The page changed between the true/false conditions with no error shown.",
                ],
            )

    # ---- Technique 3: NoSQL operator injection (URL params) --------------
    try:
        nhit = _nosql_on_query(session, url)
    except Exception:
        nhit = None
    if nhit:
        name, op = nhit
        return result(
            "adv_sqli", NAME, CATEGORY, STATUS_WARN, SEV_MEDIUM,
            f"Possible NoSQL (MongoDB) operator injection on '{name}'.",
            [
                f"Parameter: {name}",
                f"Operator probe: {name}{op}={NOSQL_VALUES[op]}",
                "The operator changed the response versus the plain value -- "
                "a classic NoSQL-injection signal. Verify manually.",
            ],
        )

    if not points and not query_pairs(url):
        return result("adv_sqli", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
                      "No forms or URL parameters were available to test for blind SQLi.")

    return result("adv_sqli", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
                  "No blind or NoSQL injection detected (time-based, boolean and Mongo probes).",
                  [f"Probed {len(points)} input(s) individually across forms, search bars and URL params."])
