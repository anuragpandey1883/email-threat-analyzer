# Email Threat Analyzer v0.6.0

Synchronized local project with a dark SOC-style dashboard and the existing FastAPI email-analysis backend.

## Setup on Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

In a second terminal, from the project root:

```powershell
python -m http.server 5500 --directory frontend
```

Open `http://127.0.0.1:5500/index.html`. API docs are at `http://127.0.0.1:8000/docs`; health is at `http://127.0.0.1:8000/health`.

## Configuration

Copy your existing private `.env` file into the project root if you use provider keys. Supported environment variables include `VT_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `ABUSEIPDB_API_KEY`, optional `GMAIL_REDIRECT_URI`, `MAX_EMAIL_MB` (default 15), `MAX_URLS` (default 100), `MAX_ATTACHMENTS` (default 20), and `MAX_ATTACHMENT_ANALYSIS_MB` (default 10). Gmail OAuth requires your own `credentials.json` and creates a private `token.json`. Do not commit or share those files.

The attachment VirusTotal flow is hash-based; it does not upload attachment bytes. Third-party URL reputation lookups may disclose URLs to those providers, so avoid sending confidential links unless their data-handling terms are acceptable.

## What changed in v0.5.0

- SOC-style dark dashboard with saved-analysis metrics, verdict distribution, recent investigations, and finding-category bars.
- Dashboard rows can reopen a saved analysis. Existing tabs and API endpoints are preserved.
- Combined generic URL heuristic scoring is capped to reduce score inflation from correlated low-quality indicators; strong reputation evidence is not capped by this rule.
- URL indicators include IP-literal hosts, private/reserved IP literals, and non-standard ports.
- Health endpoint reports YARA module availability and rules-file availability separately.

See `IMPROVEMENTS.md` and `SYNC_AND_TESTING.md` for details and limitations.

## Tests

```powershell
python -m pytest -q
node --check frontend/app.js
```

The packaged tests cover selected scoring and URL indicator behavior. They do not measure real-world precision/recall or establish browser-based end-to-end integration. Use a labelled corpus of benign and malicious samples to measure false positives and false negatives before relying on verdicts.

## Important limitations

- A LOW verdict is not proof of safety; missing API results are unknown, not clean.
- SPF is not fully evaluated locally because the SMTP client IP and trusted receiving context are not reliably available from a standalone `.eml`.
- DMARC organizational-domain alignment is approximated using exact domain equality.
- YARA detection requires a rules file. This project does not ship a curated ruleset.


### v0.5.1 viewport layout fix

The frontend stylesheet now keeps the fixed desktop sidebar separate from the main content area, accounts for the 118px header, constrains grid children to the viewport, and switches to a wrapping mobile navigation below 680px.


## v0.6.0 hardening

- Removed local OAuth token, generated logs, Python bytecode caches, and runtime storage from the distributable archive.
- Gmail OAuth callback no longer prints exception details; outstanding OAuth states are expired/pruned and bounded. Token file permissions are restricted where the operating system supports POSIX mode bits.
- Authentication reporting now explicitly distinguishes exact-domain alignment hints from a complete DMARC evaluation.
- Attachment deep parsing is skipped above `MAX_ATTACHMENT_ANALYSIS_MB`; the report explains that analysis was skipped rather than treating the attachment as clean.
- Added regression tests for malformed URLs, reserved IP literals, URL normalization, attachment size limits, and authentication alignment limitations.

Security note: if a previously shared `token.json` was real and active, revoke the app's Gmail access in your Google Account and reconnect. Do not distribute `.env`, `credentials.json`, `token.json`, logs, or real email samples.
