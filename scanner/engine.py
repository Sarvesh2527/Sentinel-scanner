"""
engine.py -- the orchestrator.

Runs every check against a target URL in sequence (each check is an independent
module owned by the security engineer), collects the structured results, and
attaches an overall score. This is the single entry point the Flask backend
calls: `run_all_checks(url)`.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from . import (
    https_check,
    headers_check,
    outdated_lib_check,
    env_check,
    idor_check,
    cors_check,
    cookie_check,
    server_cve_check,
    clickjacking_check,
    sensitive_data_check,
    mixed_content_check,
    csrf_check,
    http_methods_check,
    sri_check,
    auth_form_check,
    xss_check,
    sqli_check,
    advanced_sqli_check,
    command_injection_check,
    ssti_check,
    path_traversal_check,
    open_redirect_check,
    crlf_check,
    host_header_check,
)
from . import scoring
from .remediation import REMEDIATION
from ._common import (
    new_session, normalise_url, is_valid_target,
    result, STATUS_INFO, SEV_INFO,
)

# Ordered list of check modules. VA (assessment) checks first, then the active
# PT (penetration-test) checks. Order here is the order shown in the report.
CHECK_MODULES = [
    # --- Vulnerability Assessment (passive / read-only) ---
    https_check,
    headers_check,
    cookie_check,
    cors_check,
    clickjacking_check,
    mixed_content_check,
    sri_check,
    http_methods_check,
    outdated_lib_check,
    server_cve_check,
    sensitive_data_check,
    env_check,
    idor_check,
    csrf_check,
    auth_form_check,
    # --- Penetration Testing (active payloads) ---
    xss_check,
    sqli_check,
    advanced_sqli_check,
    command_injection_check,
    ssti_check,
    path_traversal_check,
    open_redirect_check,
    crlf_check,
    host_header_check,
]

# Each check maps to an OWASP Top 10 (2021) category. Attached to every result
# so the report and landing page can show the coverage.
OWASP_MAP = {
    "https": "A02: Cryptographic Failures",
    "headers": "A05: Security Misconfiguration",
    "cookies": "A05: Security Misconfiguration",
    "cors": "A05: Security Misconfiguration",
    "clickjacking": "A05: Security Misconfiguration",
    "mixed_content": "A02: Cryptographic Failures",
    "sri": "A08: Software & Data Integrity Failures",
    "http_methods": "A05: Security Misconfiguration",
    "outdated_lib": "A06: Vulnerable & Outdated Components",
    "server_cve": "A06: Vulnerable & Outdated Components",
    "sensitive_data": "A02: Cryptographic Failures",
    "env": "A05: Security Misconfiguration",
    "idor": "A01: Broken Access Control",
    "csrf": "A01: Broken Access Control",
    "auth_form": "A07: Identification & Authentication Failures",
    "xss": "A03: Injection",
    "sqli": "A03: Injection",
    "adv_sqli": "A03: Injection",
    "cmd_injection": "A03: Injection",
    "ssti": "A03: Injection",
    "path_traversal": "A01: Broken Access Control",
    "open_redirect": "A01: Broken Access Control",
    "crlf": "A03: Injection",
    "host_header": "A03: Injection",
}

# Lightweight metadata the frontend uses to describe checks up-front (before a
# scan runs) -- e.g. on the landing page "what we check" section.
def _reg(cid, module, category, desc):
    return {"id": cid, "name": module.NAME, "category": category,
            "owasp": OWASP_MAP.get(cid, ""), "desc": desc}


CHECK_REGISTRY = [
    _reg("https", https_check, "VA",
         "Confirms the site is served over encrypted HTTPS, not plain HTTP."),
    _reg("headers", headers_check, "VA",
         "Checks for CSP, HSTS, X-Frame-Options and other security headers."),
    _reg("cookies", cookie_check, "VA",
         "Flags session cookies missing Secure, HttpOnly or SameSite flags."),
    _reg("cors", cors_check, "VA",
         "Detects CORS setups that reflect any origin, exposing authenticated data."),
    _reg("clickjacking", clickjacking_check, "VA",
         "Flags pages that can be framed (no X-Frame-Options / CSP frame-ancestors)."),
    _reg("mixed_content", mixed_content_check, "VA",
         "Finds HTTPS pages that load scripts or frames over insecure http://."),
    _reg("sri", sri_check, "VA",
         "Flags third-party scripts/styles loaded without Subresource Integrity."),
    _reg("http_methods", http_methods_check, "VA",
         "Enumerates HTTP methods; flags TRACE (XST) and risky PUT/DELETE."),
    _reg("outdated_lib", outdated_lib_check, "VA",
         "Detects known-outdated jQuery / Bootstrap versions in the page."),
    _reg("server_cve", server_cve_check, "VA",
         "Fingerprints server/library versions and matches them to known CVEs."),
    _reg("sensitive_data", sensitive_data_check, "VA",
         "Scans the source for leaked API keys, private keys, tokens and JWTs."),
    _reg("env", env_check, "VA",
         "Probes common paths for exposed .env and secret/config files."),
    _reg("idor", idor_check, "VA",
         "Flags id-style object references worth manual IDOR testing."),
    _reg("csrf", csrf_check, "VA",
         "Flags state-changing POST forms with no anti-CSRF token."),
    _reg("auth_form", auth_form_check, "VA",
         "Checks login forms for cleartext-HTTP submission and password autocomplete."),
    _reg("xss", xss_check, "PT",
         "Reflected XSS across every form field, search bar and URL parameter."),
    _reg("sqli", sqli_check, "PT",
         "Error-based SQL injection across every input and URL parameter."),
    _reg("adv_sqli", advanced_sqli_check, "PT",
         "Blind SQLi (time-based & boolean) and NoSQL injection — no error needed."),
    _reg("cmd_injection", command_injection_check, "PT",
         "Time-based OS command injection (Unix & Windows) in every input."),
    _reg("ssti", ssti_check, "PT",
         "Server-Side Template Injection (Jinja/Twig/Freemarker/ERB/Razor)."),
    _reg("path_traversal", path_traversal_check, "PT",
         "Path traversal / LFI reading system files through user input."),
    _reg("open_redirect", open_redirect_check, "PT",
         "Open redirect (and SSRF surface) via redirect-style URL parameters."),
    _reg("crlf", crlf_check, "PT",
         "CRLF / HTTP response-header injection via URL parameters."),
    _reg("host_header", host_header_check, "PT",
         "Host header injection (reset/cache poisoning) via a spoofed Host."),
]


# Concurrency + safety limits for a scan.
MAX_WORKERS = 6          # how many checks run at once
PER_CHECK_TIMEOUT = 25   # seconds; a check exceeding this is skipped


def _run_one_check(module, url):
    """Run a single check with its own requests session (thread-safe)."""
    session = new_session()
    try:
        return module.run(session, url)
    except Exception as exc:  # a broken check must never kill the whole scan
        return result(
            getattr(module, "__name__", "check").split(".")[-1],
            getattr(module, "NAME", "Unknown check"),
            getattr(module, "CATEGORY", "VA"),
            STATUS_INFO, SEV_INFO,
            f"Check could not complete: {exc.__class__.__name__}.",
        )
    finally:
        try:
            session.close()
        except Exception:
            pass


def run_all_checks(raw_url: str) -> dict:
    """
    Run the full scan.

    Returns:
        {
          "url": <normalised url>,
          "ok": bool,                  # False if the URL was invalid
          "error": <str or None>,
          "results": [ <check dict>, ... ],
          "summary": { score, grade, ... },
          "duration_ms": int,
        }
    """
    url = normalise_url(raw_url)
    started = time.time()

    if not is_valid_target(url):
        return {
            "url": raw_url,
            "ok": False,
            "error": "That doesn't look like a valid URL. Try e.g. http://localhost:8080",
            "results": [],
            "summary": scoring.compute_score([]),
            "duration_ms": 0,
        }

    # Run all checks concurrently -- they're independent and I/O-bound, so a
    # thread pool turns the total time from "sum of every check" into roughly
    # "the slowest check". Each check gets its own session (thread-safe), and a
    # per-check timeout means one slow check can never hang the whole scan.
    results = [None] * len(CHECK_MODULES)
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    future_to_idx = {
        executor.submit(_run_one_check, module, url): i
        for i, module in enumerate(CHECK_MODULES)
    }
    for future, i in future_to_idx.items():
        try:
            results[i] = future.result(timeout=PER_CHECK_TIMEOUT)
        except Exception:
            module = CHECK_MODULES[i]
            results[i] = result(
                CHECK_REGISTRY[i]["id"],
                getattr(module, "NAME", "Unknown check"),
                getattr(module, "CATEGORY", "VA"),
                STATUS_INFO, SEV_INFO,
                "Check took too long and was skipped.",
            )
    # Don't block the response on any straggler thread; its own request timeouts
    # will end it shortly.
    executor.shutdown(wait=False)

    # Tag every result with its OWASP category and fix guidance for the report UI.
    for r in results:
        r["owasp"] = OWASP_MAP.get(r.get("id"), "")
        r["remediation"] = REMEDIATION.get(r.get("id"))

    duration_ms = int((time.time() - started) * 1000)

    # If every single check came back "info" (nothing could pass, fail or warn),
    # the host was effectively unreachable -- don't present that as a perfect
    # score. Bail out with a clear, honest error instead of saving a fake "A".
    conclusive = [r for r in results if r["status"] != STATUS_INFO]
    if not conclusive:
        return {
            "url": url,
            "ok": False,
            "error": f"Could not reach {url}. Check the URL is correct and the "
                     f"target is online (for a local target, make sure it's running).",
            "results": results,
            "summary": scoring.compute_score([]),
            "duration_ms": duration_ms,
        }

    summary = scoring.compute_score(results)

    return {
        "url": url,
        "ok": True,
        "error": None,
        "results": results,
        "summary": summary,
        "duration_ms": duration_ms,
    }


# Allow quick manual testing from the command line:
#   python -m scanner.engine http://localhost:8080
if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    report = run_all_checks(target)
    print(json.dumps(report, indent=2))
