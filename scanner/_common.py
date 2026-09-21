"""
Shared helpers for the scanning engine.

Provides a common requests session (with a sane User-Agent and timeout) and a
`result()` factory so every check returns the exact same shape. Keeping this in
one place means each check module stays tiny and focused on its own logic.
"""

from __future__ import annotations

import requests
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# A short, honest User-Agent. We identify as a scanner so target owners can see
# it in their logs -- this is a defensive/educational tool, not a stealth one.
USER_AGENT = "VAPT-Scanner/1.0 (+educational; final-year-project)"

DEFAULT_TIMEOUT = 8  # seconds -- keep scans snappy, never hang the UI

# Status vocabulary used across the whole app (backend + frontend both rely on
# these exact strings, so change them in one place only).
STATUS_PASS = "pass"   # check found no problem
STATUS_FAIL = "fail"   # check found a real weakness
STATUS_WARN = "warn"   # something worth noting, not a hard fail
STATUS_INFO = "info"   # informational / could not fully determine

# Severity is used for weighting the overall score and for colour-coding cards.
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"
SEV_INFO = "info"


def new_session() -> requests.Session:
    """Return a configured requests session shared by all checks in one scan."""
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    # Do not follow an endless redirect chain; a few hops is plenty.
    s.max_redirects = 5
    return s


def fetch(session: requests.Session, url: str, method: str = "GET", **kwargs):
    """
    Safe wrapper around session.request.

    Returns (response, error). Exactly one of them is None. Every check calls
    this instead of requests directly so timeouts / connection errors never
    crash the scan -- they just turn into a graceful "info" result.
    """
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    kwargs.setdefault("allow_redirects", True)
    try:
        resp = session.request(method, url, **kwargs)
        return resp, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL error: {e.__class__.__name__}"
    except requests.exceptions.ConnectTimeout:
        return None, "Connection timed out"
    except requests.exceptions.ReadTimeout:
        return None, "Read timed out"
    except requests.exceptions.ConnectionError:
        return None, "Could not connect to host"
    except requests.exceptions.TooManyRedirects:
        return None, "Too many redirects"
    except requests.exceptions.RequestException as e:
        return None, f"Request failed: {e.__class__.__name__}"


def result(check_id, name, category, status, severity, detail, evidence=None):
    """
    Build the standard result dict every check returns.

    check_id : short machine id, e.g. "https"
    name     : human title, e.g. "HTTPS Usage"
    category : "VA" (assessment) or "PT" (penetration test)
    status   : one of STATUS_*
    severity : one of SEV_*
    detail   : one-line human explanation shown on the report card
    evidence : optional list of strings (paths tried, headers found, etc.)
    """
    return {
        "id": check_id,
        "name": name,
        "category": category,
        "status": status,
        "severity": severity,
        "detail": detail,
        "evidence": evidence or [],
    }


def normalise_url(raw: str) -> str:
    """
    Clean up user input into a fetchable URL.

    - strips whitespace
    - adds https:// if no scheme was given
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw


def is_valid_target(url: str) -> bool:
    """Basic sanity check: must have a scheme and a host."""
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# URL query-parameter helpers -- used by every injection check so they can test
# the URL and search-bar parameters, not just <form> fields.
# --------------------------------------------------------------------------- #

# Parameter names commonly used by search boxes and object lookups. When the
# user pastes a bare URL with no query string, we probe these so a search
# endpoint like /?q=... still gets tested. Ignored params simply do nothing
# (no reflection, no error, no delay), so this never causes a false positive.
COMMON_PARAMS = ["q", "s", "search", "query", "id", "keyword"]


def combined_guess_url(url: str, payload: str, force: bool = False):
    """
    Return a single URL that sets *every* common search parameter to `payload`
    at once. This lets a check probe a possible search endpoint in one request
    instead of one-per-name; only if that probe reacts does the caller fan out
    to identify the exact parameter.

    Normally returns None when the URL already has its own query parameters
    (those real parameters get tested directly). Pass force=True -- e.g. when the
    page has a nameless search box -- to guess even alongside existing params.
    """
    if query_pairs(url) and not force:
        return None
    out = url
    for name in COMMON_PARAMS:
        out = with_query_param(out, name, payload)
    return out


def query_pairs(url: str):
    """Return the URL's query string as a list of (name, value) tuples."""
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def with_query_param(url: str, name: str, value: str) -> str:
    """Return a copy of `url` with query parameter `name` set to `value`
    (added if it wasn't already present)."""
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    out, replaced = [], False
    for k, v in pairs:
        if k == name:
            out.append((k, value)); replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(out)))
