# Email Threat Analyzer — v0.5.0 changes

## Frontend / SOC dashboard
- Reworked the dashboard into a dark SOC-style workspace with status strip, four operational metrics, verdict distribution, recent investigations, and finding-category bars.
- Dashboard metrics are calculated from saved analysis history in this browser only; they are not live inbox-wide statistics.
- Recent investigation rows open the saved analysis. Existing Analyze, History, Reports, VirusTotal, Gmail, URL/attachment tables, and current-email IP dashboard markup and API paths are retained.
- Added responsive layouts and accessible focus states without introducing a third-party chart dependency.

## Detection logic
- Generic URL heuristic findings are deduplicated and their combined score contribution is capped at 15 points so many correlated low-quality indicators do not dominate stronger evidence. Critical reputation findings retain their severity.
- URL analysis now flags IP-literal hosts, private/reserved IP literals, and non-standard ports as additional indicators.
- The API health endpoint now reports YARA module availability separately from whether a YARA rules file exists; a module installed without a rules file is not presented as active rules coverage.
- API/application version is 0.5.0.

## Validation performed in this build
- Backend unit tests: 9 passed.
- Frontend JavaScript syntax check: run separately where Node.js is available.
- Endpoint smoke tests and browser-based end-to-end integration should be performed in the user's environment.

## Limitations
- No labelled email corpus was supplied, so real-world accuracy, precision, recall, and false-positive/false-negative rates have not been measured.
- SPF is not fully evaluated locally because a raw `.eml` file does not necessarily provide a trustworthy SMTP client IP and receiver context.
- DMARC organizational-domain alignment remains approximated using exact domain equality.
- Reputation data can be unavailable, stale, rate-limited, or incomplete; an unknown result is not proof of safety.
- YARA rules coverage depends on a rules file being present. This package does not add a curated YARA ruleset.
