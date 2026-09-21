"""
crlf_check.py -- CRLF / HTTP response-header injection (OWASP A03: Injection).

If a parameter value is copied into a response header without stripping CR/LF,
an attacker can inject `\\r\\n` to add their own headers (e.g. Set-Cookie) or
split the response. We inject an encoded CRLF followed by a marker header into
each URL parameter and check whether that header appears in the response.
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, quote

from ._common import (
    fetch, result, SEV_MEDIUM,
    STATUS_PASS, STATUS_FAIL, STATUS_INFO,
)

NAME = "CRLF / Header Injection"
CATEGORY = "PT"
OWASP = "A03: Injection"

TIMEOUT = 10
MARKER_HEADER = "X-Vapt-Injected"
# encoded CRLF variants an app might decode before writing the header
CRLF_VARIANTS = ["%0d%0a", "%0a", "%E5%98%8A%E5%98%8D"]


def _raw_probe_url(base_root, other_pairs, name, encoded_value):
    """Build a URL where `name`'s value is already percent-encoded (so our CRLF
    survives to the server), keeping the other params intact."""
    prefix = urlencode(other_pairs)
    q = (prefix + "&" if prefix else "") + f"{name}={encoded_value}"
    return f"{base_root}?{q}"


def run(session, url: str) -> dict:
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    pairs = parse_qsl(parsed.query, keep_blank_values=True)

    # Only test the URL's real parameters -- header injection through guessed
    # parameter names is very low-yield and not worth the extra requests.
    names = [n for n, _ in pairs]
    if not names:
        return result("crlf", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      "No URL parameters were available to test for CRLF injection.")
    tested = 0

    for name in names:
        others = [(k, v) for k, v in pairs if k != name]
        for crlf in CRLF_VARIANTS:
            payload = "vapt" + crlf + f"{MARKER_HEADER}: pwned"
            encoded = quote(payload, safe="%")  # keep our %0d%0a literal
            probe = _raw_probe_url(root, others, name, encoded)
            resp, err = fetch(session, probe, method="get",
                              allow_redirects=False, timeout=TIMEOUT)
            if err or resp is None:
                continue
            tested += 1
            # header names are case-insensitive in requests' dict
            if MARKER_HEADER.lower() in {k.lower() for k in resp.headers.keys()}:
                return result(
                    "crlf", NAME, CATEGORY, STATUS_FAIL, SEV_MEDIUM,
                    f"CRLF injection: parameter '{name}' let us inject a response header.",
                    [
                        f"Injection point: URL parameter '{name}'",
                        f"Request: {probe}",
                        f"Injected header reflected back: {MARKER_HEADER}: pwned",
                    ],
                )

    if tested == 0:
        return result("crlf", NAME, CATEGORY, STATUS_INFO, SEV_MEDIUM,
                      "No URL parameters were available to test for CRLF injection.")

    return result("crlf", NAME, CATEGORY, STATUS_PASS, SEV_MEDIUM,
                  f"No CRLF / header injection detected across {tested} probe(s).",
                  ["Injected encoded CR/LF + marker header; it never appeared in the response."])
