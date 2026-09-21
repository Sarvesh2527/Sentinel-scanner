# Sentinel — Automated Web Application VAPT Scanner

A full-stack **Vulnerability Assessment & Penetration Testing** tool. Enter a
target URL, and Sentinel runs seven automated security checks, then renders a
scored, readable report. Built as a final-year project.

- **Security engine (Python):** independent modules, one per check — *Sarvesh*
- **Full-stack platform (Flask + SQLite + JS):** API, database, UI — *Ronit*

---

## What it checks — 24 checks across the OWASP Top 10 (2021)

| # | Check | Type | OWASP | What it does |
|---|-------|------|-------|--------------|
| 1 | HTTPS Usage | VA | A02 | Confirms the site is served over HTTPS, not plain HTTP |
| 2 | Security Headers | VA | A05 | Checks for CSP, X-Frame-Options, HSTS, and more |
| 3 | Cookie Security | VA | A05 | Flags cookies missing Secure / HttpOnly / SameSite |
| 4 | CORS Misconfiguration | VA | A05 | Detects setups that reflect any Origin with credentials |
| 5 | Clickjacking | VA | A05 | Page frameable (no X-Frame-Options / CSP frame-ancestors) |
| 6 | Mixed Content | VA | A02 | HTTPS page loading `http://` scripts/frames |
| 7 | Subresource Integrity | VA | A08 | Cross-origin scripts/styles without `integrity` |
| 8 | HTTP Methods | VA | A05 | Dangerous methods enabled (TRACE→XST, PUT/DELETE) |
| 9 | Outdated JS Libraries | VA | A06 | Detects old jQuery / Bootstrap versions in the page |
| 10 | Known CVEs / Components | VA | A06 | Version banners → known CVEs (e.g. CVE-2021-41773) |
| 11 | Sensitive Data Exposure | VA | A02 | Leaked API keys, private keys, JWTs, tokens in source |
| 12 | .env File Exposure | VA | A05 | Probes common paths for exposed config/secret files |
| 13 | IDOR Pattern Detection | VA | A01 | Flags `id=`, `user_id=` style object references |
| 14 | CSRF Protection | VA | A01 | State-changing POST forms with no anti-CSRF token |
| 15 | Login Form Security | VA | A07 | Credentials over HTTP, password autocomplete |
| 16 | Reflected XSS | PT | A03 | Benign payload into every input + URL param; checks reflection |
| 17 | SQL Injection | PT | A03 | Breaker payloads into every input + URL param; DB error signatures |
| 18 | Advanced SQL Injection | PT | A03 | Blind (time-based + boolean) and NoSQL injection — no error needed |
| 19 | Command Injection | PT | A03 | Time-based OS command injection (Unix `sleep` / Windows `ping`) |
| 20 | Template Injection (SSTI) | PT | A03 | Injects `{{9999*9999}}` etc.; detects the evaluated result |
| 21 | Path Traversal / LFI | PT | A01 | `../../etc/passwd` payloads; matches file-content signatures |
| 22 | Open Redirect | PT | A01 | Redirect-style params → external marker in `Location` (also SSRF surface) |
| 23 | CRLF / Header Injection | PT | A03 | Encoded CR/LF in URL params → injected response header |
| 24 | Host Header Injection | PT | A03 | Spoofed `Host` reflected → reset/cache poisoning |

Results feed a **scoring system** (0–100 + A–F grade). Every failed/warned
finding has a **"How to fix"** button that expands step-by-step remediation
guidance and a code snippet (see `scanner/remediation.py`).

### OWASP Top 10 coverage (7 of 10 categories)

| Category | Covered by |
|----------|-----------|
| A01 Broken Access Control | IDOR, CSRF, Path Traversal, Open Redirect |
| A02 Cryptographic Failures | HTTPS, Mixed Content, Sensitive Data Exposure |
| A03 Injection | XSS, SQLi, Advanced SQLi, Command Injection, SSTI, CRLF, Host Header |
| A05 Security Misconfiguration | Headers, Cookies, CORS, Clickjacking, HTTP Methods, .env |
| A06 Vulnerable & Outdated Components | Outdated Libraries, Known CVEs |
| A07 Identification & Auth Failures | Login Form Security |
| A08 Software & Data Integrity | Subresource Integrity |
| A10 SSRF | Open Redirect (server-side-fetch surface) |

A04 (Insecure Design) and A09 (Logging & Monitoring) are **design/process**
controls that can't be confirmed by an unauthenticated remote scan, so they're
out of scope.

### Advanced SQL injection — what most scanners miss

Check #7 is *error-based*: it only works when the target echoes a database
error. Modern apps suppress errors, so that class of scan misses real, still-
injectable endpoints. Check #8 (`advanced_sqli_check.py`) covers the classes
that produce **no error and no visible output**:

- **Time-based blind** — injects a DB `SLEEP()` / `pg_sleep()` / `WAITFOR DELAY`
  and infers injection from the response *delay*. A finding is only reported
  after a **second, longer sleep scales proportionally** (3s → 6s), so slow
  pages and network jitter don't cause false positives. Fingerprints MySQL,
  PostgreSQL, MSSQL and Oracle.
- **Boolean-based blind** — sends an always-true (`1=1`) and always-false
  (`1=2`) condition and detects injection from the *content differential*.
- **NoSQL (MongoDB) operator injection** — the newest and most-ignored class.
  Modern Express/Mongo stacks parse `param[$ne]=x` into a query operator;
  classic SQLi scanners never test it. Probes `$ne`, `$gt` and `$regex`.

All payloads are non-destructive (sleeps, boolean conditions, read-only operator
probes) — nothing reads, writes or deletes data.

### Injection surfaces tested

Every injection check (XSS, SQLi, advanced blind/NoSQL, command injection, SSTI,
path traversal) tests each input **individually** across **four** surfaces:

1. **Form fields** — every text input and textarea inside a `<form>`.
2. **Search boxes** — including standalone `<input type="search">` boxes that
   are **not** wrapped in a form (the JavaScript-driven search bars that
   form-only scanners skip). Detected by type / name / id / placeholder /
   `aria-label` / class, tested first, and labelled *"search box '<name>'"* in
   the report. A nameless search box triggers the common-parameter guess below.
3. **URL query parameters** — each parameter in the URL you submit (e.g.
   `?id=1`), tested individually — the classic blind-SQLi entry point.
4. **Guessed search parameters** — common names (`q`, `s`, `search`, `query`,
   `id`, `keyword`) probed in a single combined request when the URL is bare or
   a nameless search box is present. (Ignored parameters do nothing, so this
   never causes a false positive.)

---

## Project structure

```
Buggy kaal/
├── app.py                 # Flask backend + REST API (Ronit)
├── database.py            # SQLite persistence for scan history (Ronit)
├── scanner/               # Python scanning engine (Sarvesh)
│   ├── __init__.py
│   ├── _common.py               # shared HTTP + result + URL-param helpers
│   ├── points.py                # per-input injection points + time-based probe
│   ├── https_check.py           # A02
│   ├── headers_check.py         # A05
│   ├── cookie_check.py          # A05
│   ├── cors_check.py            # A05
│   ├── outdated_lib_check.py    # A06
│   ├── server_cve_check.py      # A06  known-CVE version fingerprinting
│   ├── env_check.py             # A05
│   ├── idor_check.py            # A01
│   ├── xss_check.py             # A03
│   ├── sqli_check.py            # A03  error-based SQLi
│   ├── advanced_sqli_check.py   # A03  blind (time/boolean) + NoSQL
│   ├── command_injection_check.py  # A03  time-based OS command injection
│   ├── ssti_check.py            # A03  server-side template injection
│   ├── path_traversal_check.py  # A01  path traversal / LFI
│   ├── open_redirect_check.py   # A01  open redirect / SSRF surface
│   ├── crlf_check.py            # A03  CRLF / header injection
│   ├── scoring.py               # combines results into one score
│   └── engine.py                # orchestrator: run_all_checks(url)
├── templates/
│   ├── index.html         # landing + scanner + live report
│   └── history.html       # past scans
├── static/
│   ├── css/style.css      # Apple-inspired design system
│   └── js/
│       ├── app.js         # scan flow, report rendering, score ring
│       └── history.js     # history list, delete, clear
├── requirements.txt
└── README.md
```

---

## Running it

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the app
python app.py

# 3. Open the browser
#    http://127.0.0.1:5000
```

The SQLite database (`scans.db`) is created automatically on first run. Scan
history **auto-prunes to the 3 most recent scans** — after each new scan the
oldest is deleted. Change the limit with `MAX_HISTORY` in `database.py`.

### Try the engine on its own (no web server)

```bash
python -m scanner.engine https://example.com
```

---

## REST API

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/checks` | Metadata about the checks |
| POST | `/api/scan` | Run a scan — body `{"url": "..."}` |
| GET | `/api/history` | List recent scans |
| GET | `/api/scan/<id>` | Reopen one saved scan |
| DELETE | `/api/scan/<id>` | Delete one scan |
| DELETE | `/api/history` | Clear all history |

---

## Ethical / legal note

Active exploitation checks (XSS and SQL injection submission) are intended for
**intentionally vulnerable practice applications** — DVWA and OWASP Juice Shop —
run locally in Docker. **Only scan systems you own or are explicitly authorised
to test.**

### Setting up a safe test target (DVWA in Docker)

```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
# then scan  http://localhost:8080
```
