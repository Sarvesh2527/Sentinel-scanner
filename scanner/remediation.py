"""
remediation.py -- fix guidance for every check.

Keyed by check id. Each entry has a one-line `summary`, a few concrete `steps`,
and an optional `code` snippet. The engine attaches the matching entry to every
result so the frontend can show a "How to fix" panel on each finding.
"""

REMEDIATION = {
    "https": {
        "summary": "Serve the whole site over HTTPS and force HTTP to redirect.",
        "steps": [
            "Install a TLS certificate (free via Let's Encrypt / Certbot).",
            "301-redirect every http:// request to its https:// equivalent.",
            "Enable HSTS so browsers refuse to connect over plain HTTP.",
        ],
        "code": "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    },
    "headers": {
        "summary": "Add the missing security response headers.",
        "steps": [
            "Set a Content-Security-Policy to control where resources load from.",
            "Add X-Frame-Options, X-Content-Type-Options and Referrer-Policy.",
            "Apply them globally in your server/reverse-proxy or app middleware.",
        ],
        "code": ("Content-Security-Policy: default-src 'self'\n"
                 "X-Frame-Options: DENY\n"
                 "X-Content-Type-Options: nosniff\n"
                 "Referrer-Policy: no-referrer-when-downgrade"),
    },
    "cookies": {
        "summary": "Mark session cookies Secure, HttpOnly and SameSite.",
        "steps": [
            "Secure = only sent over HTTPS.",
            "HttpOnly = not readable from JavaScript (limits XSS impact).",
            "SameSite=Strict or Lax = mitigates CSRF.",
        ],
        "code": "Set-Cookie: sessionid=...; Secure; HttpOnly; SameSite=Strict; Path=/",
    },
    "cors": {
        "summary": "Never reflect an arbitrary Origin; use a strict allow-list.",
        "steps": [
            "Compare the request Origin against a fixed allow-list of trusted sites.",
            "Only echo Access-Control-Allow-Origin for an allowed Origin.",
            "Never combine Access-Control-Allow-Credentials: true with '*' or reflection.",
        ],
    },
    "clickjacking": {
        "summary": "Stop the page from being framed by other sites.",
        "steps": [
            "Add X-Frame-Options: DENY (or SAMEORIGIN if you frame your own pages).",
            "Or use a CSP frame-ancestors directive, which supersedes it.",
        ],
        "code": "Content-Security-Policy: frame-ancestors 'none'",
    },
    "mixed_content": {
        "summary": "Load every sub-resource over HTTPS.",
        "steps": [
            "Change http:// script/iframe/link/img URLs to https:// (or relative).",
            "Add CSP: upgrade-insecure-requests to auto-upgrade legacy links.",
        ],
        "code": "Content-Security-Policy: upgrade-insecure-requests",
    },
    "sri": {
        "summary": "Pin third-party scripts/styles with Subresource Integrity.",
        "steps": [
            "Add an integrity=\"sha384-...\" hash to each cross-origin <script>/<link>.",
            "Add crossorigin=\"anonymous\" so the browser can verify the hash.",
            "Generate hashes at build time or from the CDN's SRI helper.",
        ],
        "code": '<script src="https://cdn/lib.js" integrity="sha384-…" crossorigin="anonymous"></script>',
    },
    "http_methods": {
        "summary": "Disable TRACE and any write methods you don't use.",
        "steps": [
            "Turn off TRACE at the web server (it enables Cross-Site Tracing).",
            "Restrict PUT/DELETE/PATCH to authenticated API routes that need them.",
            "Return 405 for methods an endpoint should not accept.",
        ],
    },
    "outdated_lib": {
        "summary": "Upgrade the outdated front-end library to a patched version.",
        "steps": [
            "Update jQuery to >= 3.5.0 and Bootstrap to >= 4.3.1 / latest 5.x.",
            "Pull libraries from your package manager, not copy-pasted files.",
            "Automate dependency updates (Dependabot / Renovate).",
        ],
    },
    "server_cve": {
        "summary": "Patch the flagged component and hide version banners.",
        "steps": [
            "Upgrade the affected server/runtime/library to a fixed release.",
            "Remove version numbers from Server / X-Powered-By headers.",
            "Track advisories for your stack and patch on a schedule.",
        ],
        "code": "# Apache: ServerTokens Prod / ServerSignature Off\n# Nginx: server_tokens off;",
    },
    "sensitive_data": {
        "summary": "Remove secrets from client code and rotate anything exposed.",
        "steps": [
            "Delete keys/tokens from HTML/JS; keep them server-side only.",
            "Immediately rotate any credential that was exposed.",
            "Load secrets from environment variables / a secrets manager.",
        ],
    },
    "env": {
        "summary": "Block public access to config and dotfiles.",
        "steps": [
            "Deny web access to .env, .git, *.bak and similar files.",
            "Keep secrets outside the web root entirely.",
            "Serve only a known allow-list of static paths.",
        ],
        "code": "location ~ /\\.(env|git) { deny all; return 404; }",
    },
    "idor": {
        "summary": "Enforce per-object authorization on every request.",
        "steps": [
            "Check the current user owns/may access the requested object id.",
            "Prefer unguessable identifiers (UUIDs) over sequential integers.",
            "Never rely on the client to send the 'right' id only.",
        ],
    },
    "csrf": {
        "summary": "Protect state-changing requests with anti-CSRF tokens.",
        "steps": [
            "Add a per-session, unpredictable CSRF token to every POST form.",
            "Reject requests whose token is missing or wrong.",
            "Set SameSite=Lax/Strict on session cookies as defence in depth.",
        ],
    },
    "auth_form": {
        "summary": "Submit credentials only over HTTPS.",
        "steps": [
            "Serve the login page and its form action over https://.",
            "Set autocomplete=\"current-password\" / \"new-password\" appropriately.",
            "Add rate limiting and consider multi-factor authentication.",
        ],
    },
    "xss": {
        "summary": "Context-encode all user input and add a CSP.",
        "steps": [
            "HTML-encode output; let your framework auto-escape templates.",
            "Never build HTML by concatenating raw user input.",
            "Add a Content-Security-Policy as a second layer of defence.",
        ],
        "code": "Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "sqli": {
        "summary": "Use parameterized queries — never string-concatenate SQL.",
        "steps": [
            "Bind user input as query parameters / prepared statements.",
            "Use an ORM or query builder that parameterizes by default.",
            "Give the DB account least privilege; validate input types.",
        ],
        "code": "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
    },
    "adv_sqli": {
        "summary": "Parameterize every query; the same fix stops blind SQLi.",
        "steps": [
            "Use prepared statements / bound parameters everywhere.",
            "Validate and type-cast inputs before they reach the query.",
            "Run the app with a least-privilege database user.",
        ],
        "code": "db.query(\"SELECT * FROM items WHERE id = $1\", [id])",
    },
    "cmd_injection": {
        "summary": "Don't pass user input to a shell.",
        "steps": [
            "Use language APIs instead of shelling out (e.g. libraries, not os.system).",
            "If you must exec, pass args as a list and never through a shell string.",
            "Allow-list permitted values; reject shell metacharacters.",
        ],
        "code": "subprocess.run([\"ping\", \"-c\", \"1\", host])  # args as a list, no shell=True",
    },
    "ssti": {
        "summary": "Never render user input as a template.",
        "steps": [
            "Pass user data as template *variables*, not as the template source.",
            "Use logic-less / sandboxed templating for user-supplied content.",
            "Escape output for the correct context.",
        ],
        "code": "render_template(\"page.html\", name=user_input)  # data, not template",
    },
    "path_traversal": {
        "summary": "Validate file paths and keep user input out of them.",
        "steps": [
            "Map user input to an allow-list of permitted files/ids, not raw paths.",
            "Canonicalize the path and confirm it stays inside the intended folder.",
            "Reject '..', encoded traversal and absolute paths.",
        ],
        "code": "safe = os.path.realpath(os.path.join(BASE, name))\nassert safe.startswith(BASE)",
    },
    "open_redirect": {
        "summary": "Only redirect to URLs you control.",
        "steps": [
            "Validate the target against an allow-list of internal paths/hosts.",
            "Prefer relative redirects; strip absolute external URLs.",
            "If the value is fetched server-side, block internal ranges (SSRF).",
        ],
    },
    "crlf": {
        "summary": "Strip CR/LF from anything placed into a response header.",
        "steps": [
            "Remove/encode \\r and \\n before writing header values.",
            "Use your framework's header API rather than building raw responses.",
            "Validate redirect/location values against an allow-list.",
        ],
    },
    "host_header": {
        "summary": "Don't trust the incoming Host header.",
        "steps": [
            "Validate Host against an allow-list of your canonical domains.",
            "Build absolute URLs from a configured base URL, not from request.Host.",
            "Reject requests with an unexpected Host / X-Forwarded-Host.",
        ],
    },
}
