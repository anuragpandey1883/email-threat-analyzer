# Email Threat Analyzer v0.6.0 — implementation guide (Windows)

## 1. Install safely

1. Stop the old backend and frontend terminals with `Ctrl+C`.
2. Keep a backup of the current project folder.
3. Extract this ZIP into a new folder (recommended: `email_threat_analyzer_v0.6.0`).
4. Do **not** copy old `token.json`, `logs/`, `.env`, or real email data into a shared ZIP. If you use Gmail integration, copy your private `credentials.json` only into your local working folder and reconnect Gmail through the app.

## 2. Install dependencies

Open PowerShell in the extracted project folder:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can run `.venv\Scripts\python.exe -m pip install -r requirements.txt` and use `.venv\Scripts\python.exe` for subsequent commands.

## 3. Configure optional online reputation

Create a local `.env` file only if you need provider integrations. Add your own keys, for example:

```dotenv
VT_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
MAX_EMAIL_MB=15
MAX_URLS=100
MAX_ATTACHMENTS=20
MAX_ATTACHMENT_ANALYSIS_MB=10
```

Never share `.env` or screenshots that reveal keys. URL reputation services receive the URLs being checked. Attachment VirusTotal lookup uses the SHA-256 hash and does not upload file bytes.

## 4. Start the application

Terminal 1, from the project root:

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Terminal 2, from the same project root:

```powershell
.venv\Scripts\python.exe -m http.server 5500 --directory frontend
```

Open `http://127.0.0.1:5500/index.html`. API documentation: `http://127.0.0.1:8000/docs`; health: `http://127.0.0.1:8000/health`.

## 5. Run tests

From the project root:

```powershell
.venv\Scripts\python.exe -m pytest -q
node --check frontend/app.js
```

The test suite is a regression check, not proof of real-world detection accuracy. For a measured evaluation, prepare a manually reviewed CSV with `file,label` columns (`label` is `malicious` or `benign`) and JSON analysis reports in a folder, then run:

```powershell
.venv\Scripts\python.exe tests\evaluate_corpus.py labels.csv reports
```

The evaluator treats HIGH/CRITICAL as a malicious prediction. Do not tune scoring thresholds on the final test set; use separate training/validation and test samples.

## 6. What v0.6.0 changes

- Excludes OAuth token files, runtime logs, bytecode caches, and runtime storage from the distributed archive.
- Stops printing OAuth callback exception details to the console; bounds and expires OAuth state entries; restricts token file permissions where supported.
- Makes it explicit that the analyzer's exact-domain alignment is only a hint, not a full DMARC evaluation.
- Adds a configurable size limit for deep attachment analysis. Oversized files are reported as skipped rather than silently considered clean.
- Adds regression tests and a local labeled-corpus metrics script.

## Limitations to keep in mind

- SPF cannot be independently evaluated accurately from a standalone `.eml` without a trustworthy SMTP client IP and receiving context.
- Header-reported SPF/DKIM/DMARC results can be forged if their provenance is not trusted.
- DMARC organizational-domain alignment is not fully implemented in this version.
- External reputation services may be unavailable, rate-limited, or return unknown/not-found results; unknown does not mean safe.
- The app has not been tested against your actual Gmail account or browser in this packaging environment. Run the checks above on your Windows machine before relying on it.
