"""
points.py -- injection-point enumeration + a shared time-based probe.

An "injection point" is a single place we can put a payload: ONE form field, or
ONE URL query parameter. Testing each input individually (rather than filling a
whole form at once) is more thorough and lets a finding name the exact field or
parameter that is vulnerable.

Every injection check (SQLi, XSS, command injection, SSTI, path traversal, …)
builds its points from here so behaviour is consistent across the whole engine.
"""

from __future__ import annotations

import time
from urllib.parse import urljoin

from bs4 import BeautifulSoup  # noqa: F401  (imported for callers' convenience)

from ._common import fetch, query_pairs, with_query_param

# Safety cap: never test more than this many inputs in one check, so a page
# with an enormous form can't make a scan run away. Heavy checks (time-based
# blind SQLi, command injection) pass a smaller limit of their own.
MAX_POINTS = 6


class Point:
    """One injection point. `send(session, value, timeout)` puts `value` into
    just this input and returns (elapsed_seconds, response) or (None, None)."""

    __slots__ = ("label", "seed", "kind", "_sender")

    def __init__(self, label, seed, kind, sender):
        self.label = label      # human description, e.g. "URL parameter 'id'"
        self.seed = seed        # a representative current value
        self.kind = kind        # "form" or "url"
        self._sender = sender

    def send(self, session, value, timeout):
        return self._sender(session, value, timeout)


def _timed(session, method, url, timeout, **kwargs):
    start = time.time()
    resp, err = fetch(session, url, method=method, timeout=timeout, **kwargs)
    if err or resp is None:
        return None, None
    return time.time() - start, resp


# Words that mark an input as a search box (checked in type / name / id /
# placeholder / aria-label / class).
_SEARCH_WORDS = ("search", "query", "keyword", "lookup", "find")
_SKIP_TYPES = ("submit", "button", "image", "file", "hidden",
               "checkbox", "radio", "reset", "password")


def has_search_input(soup) -> bool:
    """True if the page has any search-like input (even a nameless one)."""
    return any(_is_search_like(i) for i in soup.find_all(["input", "textarea"]))


def _is_search_like(inp) -> bool:
    if (inp.get("type") or "").lower() == "search":
        return True
    cls = inp.get("class")
    hay = " ".join(filter(None, [
        inp.get("name", ""), inp.get("id", ""), inp.get("placeholder", ""),
        inp.get("aria-label", ""), inp.get("role", ""),
        " ".join(cls) if cls else "",
    ])).lower()
    return any(w in hay for w in _SEARCH_WORDS)


def form_points(soup, base_url):
    """Yield one Point per *editable* field of every form on the page."""
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        target = urljoin(base_url, action)

        base_data, editable = {}, []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            base_data[name] = inp.get("value", "")
            itype = (inp.get("type") or "text").lower()
            if itype not in _SKIP_TYPES:
                editable.append((name, inp))

        for field, el in editable:
            seed = base_data.get(field) or "1"
            kind = "search box" if _is_search_like(el) else "form field"

            def make_sender(field=field, method=method, target=target,
                            base_data=dict(base_data)):
                def sender(session, value, timeout):
                    data = dict(base_data)
                    data[field] = value
                    kw = {"data": data} if method == "post" else {"params": data}
                    return _timed(session, method, target, timeout, **kw)
                return sender

            yield Point(f"{kind} '{field}' ({method.upper()} {target})",
                        seed, "form", make_sender())


def standalone_input_points(soup, base_url):
    """
    Yield a Point for each search box / text input that is NOT inside a <form>.

    These are the JavaScript-driven search boxes (very common on modern sites)
    that a form-only scanner completely ignores. We can't see the JS submission,
    so we test the most common pattern: the input's name/id submitted as a GET
    query parameter on the current page.
    """
    for inp in soup.find_all(["input", "textarea"]):
        if inp.find_parent("form"):
            continue  # already covered by form_points
        itype = (inp.get("type") or "text").lower()
        if itype in _SKIP_TYPES:
            continue
        param = inp.get("name") or inp.get("id")
        if not param:
            continue  # nameless inputs are handled by the search-param guess
        seed = inp.get("value") or "1"
        kind = "search box" if _is_search_like(inp) else "input field"

        def make_sender(param=param):
            def sender(session, value, timeout):
                probe = with_query_param(base_url, param, value)
                return _timed(session, "get", probe, timeout)
            return sender

        yield Point(f"{kind} '{param}' (GET {base_url})", seed, "input", make_sender())


def url_points(url):
    """Yield one Point per existing URL query parameter."""
    for name, value in query_pairs(url):
        def make_sender(name=name):
            def sender(session, value_, timeout):
                probe = with_query_param(url, name, value_)
                return _timed(session, "get", probe, timeout)
            return sender
        yield Point(f"URL parameter '{name}'", value or "1", "url", make_sender())


def enumerate_points(url, soup, limit=MAX_POINTS):
    """
    All individually-testable inputs. Search boxes are tested FIRST (they're the
    most common injection surface), then other form fields, standalone inputs
    and URL parameters. Duplicate labels are collapsed.
    """
    pts = (list(form_points(soup, url))
           + list(standalone_input_points(soup, url))
           + list(url_points(url)))
    # search boxes first
    pts.sort(key=lambda p: 0 if "search box" in p.label else 1)
    seen, uniq = set(), []
    for p in pts:
        if p.label in seen:
            continue
        seen.add(p.label)
        uniq.append(p)
    return uniq[:limit]


# --------------------------------------------------------------------------- #
# Shared time-based (blind) probe -- used by blind SQLi and command injection.
# --------------------------------------------------------------------------- #
def time_based_probe(session, point, template_groups, base_delay, confirm_delay,
                     timeout, margin=0.75, value_builder=None):
    """
    Detect a time-based blind vulnerability at `point`.

    template_groups : dict {label: [payload_template, ...]} where each template
                      contains "{S}" for the sleep seconds. `label` is e.g. the
                      DBMS ("MySQL") or shell family ("Unix shell").
    value_builder   : optional fn(seed, payload) -> value actually sent. Defaults
                      to sending the payload as-is (full replacement).

    Returns (label, template) on a CONFIRMED hit (a longer sleep scaled up),
    else None. The confirmation step is what prevents slow-page false positives.
    """
    if value_builder is None:
        value_builder = lambda seed, payload: payload  # noqa: E731

    # baseline: average of two benign round-trips
    samples = []
    for _ in range(2):
        elapsed, _r = point.send(session, point.seed, timeout)
        if elapsed is not None:
            samples.append(elapsed)
    if not samples:
        return None
    baseline = sum(samples) / len(samples)

    for label, templates in template_groups.items():
        for tmpl in templates:
            value = value_builder(point.seed, tmpl.format(S=base_delay))
            elapsed, _r = point.send(session, value, timeout)
            if elapsed is None:
                continue
            if elapsed >= baseline + base_delay * margin:
                cvalue = value_builder(point.seed, tmpl.format(S=confirm_delay))
                celapsed, _c = point.send(session, cvalue, timeout)
                if celapsed is not None and \
                   celapsed >= baseline + confirm_delay * margin and \
                   celapsed > elapsed + 1:
                    return label, tmpl
    return None
