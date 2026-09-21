"""
env_check.py -- tries common config/secret file paths and flags any that are
publicly readable.

Leaving a .env, .git/config or backup file exposed can leak database
credentials, API keys and source code. We request a small list of well-known
sensitive paths and treat any that return 200 with plausible content as a
finding. We are careful NOT to treat a soft-404 (200 page that's really the
site's HTML error page) as a hit.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ._common import (
    fetch, result, SEV_HIGH,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
)

NAME = ".env File Exposure"
CATEGORY = "VA"

# Common sensitive paths. Kept short and read-only -- we only GET these.
SENSITIVE_PATHS = [
    ".env",
    ".env.local",
    ".env.backup",
    "config.php.bak",
    ".git/config",
    ".git/HEAD",
    "wp-config.php.bak",
    "backup.sql",
    ".DS_Store",
]

# Signatures that suggest the response really is a config/secret file rather
# than an HTML error page.
POSITIVE_SIGNATURES = (
    "DB_PASSWORD", "DB_USERNAME", "DB_HOST", "APP_KEY", "SECRET",
    "[core]", "ref:", "API_KEY", "AWS_", "password",
)


def _looks_like_real_file(text: str, path: str) -> bool:
    """Heuristic: is this actually a secret file, not the site's 404 page?"""
    low = text.lower()
    # An HTML doctype almost always means we hit a normal web page / error page.
    if "<!doctype html" in low or "<html" in low:
        return False
    if not text.strip():
        return False
    # .git/HEAD is tiny and starts with "ref:"; .DS_Store is binary-ish.
    if any(sig.lower() in low for sig in POSITIVE_SIGNATURES):
        return True
    # .env files are key=value lines; a short non-HTML body with '=' is suspicious.
    if path.startswith(".env") and "=" in text and len(text) < 4000:
        return True
    return False


def run(session, url: str) -> dict:
    # Ensure we build paths against the site root.
    base = url if url.endswith("/") else url + "/"

    exposed = []
    checked = []

    for path in SENSITIVE_PATHS:
        target = urljoin(base, path)
        resp, err = fetch(session, target, allow_redirects=False)
        if err:
            continue
        checked.append(path)
        if resp.status_code == 200 and _looks_like_real_file(resp.text, path):
            exposed.append(path)

    if not checked:
        return result(
            "env", NAME, CATEGORY, STATUS_INFO, SEV_HIGH,
            "Could not probe for exposed files (host unreachable).",
        )

    if exposed:
        return result(
            "env", NAME, CATEGORY, STATUS_FAIL, SEV_HIGH,
            f"Sensitive file(s) publicly accessible: {', '.join(exposed)}.",
            [f"EXPOSED: {urljoin(base, p)}" for p in exposed],
        )

    return result(
        "env", NAME, CATEGORY, STATUS_PASS, SEV_HIGH,
        f"No common sensitive files were exposed ({len(checked)} paths probed).",
        [f"Checked: {p}" for p in checked],
    )
