# Email Threat Analyzer v0.5.0 — synchronized project

## Run on Windows
1. Extract the ZIP to a new folder first; keep your existing project as a rollback copy.
2. Open a terminal in the extracted `email_project_work` directory.
3. Activate a compatible existing virtual environment, or create one with `python -m venv .venv` and activate `.venv\\Scripts\\Activate.ps1`.
4. Install/update dependencies: `python -m pip install -r requirements.txt`.
5. Copy your private `.env` into this project root if you use provider API keys. Keep `credentials.json` and `token.json` private; Gmail OAuth may require reconnecting.
6. Start backend terminal: `python -m uvicorn app.main:app --reload`.
7. Start a second terminal from the project root: `python -m http.server 5500 --directory frontend`.
8. Open `http://127.0.0.1:5500/index.html`.
9. Check `http://127.0.0.1:8000/health` and `http://127.0.0.1:8000/docs`.

## Preserved interfaces
- Frontend API base: `http://127.0.0.1:8000`.
- Routes used include `/health`, `/analyze`, `/auth/gmail/*`, `/gmail/messages`, `/gmail/messages/{message_id}/analyze`, and `/version`.
- CORS allows `http://127.0.0.1:5500` and `http://localhost:5500`.
- Google OAuth redirect URI should match `http://127.0.0.1:8000/auth/gmail/callback` unless `GMAIL_REDIRECT_URI` is set differently.

## Data scope / caveats
- Dashboard metrics read the browser's local analysis history. Clearing browser storage clears these dashboard counts; they are not server-wide telemetry.
- Keep `.env`, Google credentials/tokens, real emails, and API keys out of shared ZIPs and version control.
- Test with benign and known-malicious sample emails before relying on verdicts. Do not open attachments or visit suspicious URLs during testing.
- Unit tests and syntax checks do not establish real-world detection accuracy; that requires a labelled test corpus and measured false-positive/false-negative rates.
