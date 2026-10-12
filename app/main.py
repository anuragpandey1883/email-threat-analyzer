import logging, os, tempfile
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .analyzer import analyze


load_dotenv()
BASE_DIR=Path(__file__).resolve().parent.parent
for d in ["logs","storage/quarantine","storage/temp","storage/reports"]:
    (BASE_DIR/d).mkdir(parents=True,exist_ok=True)

logging.basicConfig(filename=BASE_DIR/"logs/analyzer.log",level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger=logging.getLogger("email-threat-analyzer")
app=FastAPI(title="Email & Link Threat Analyzer",version="0.6.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def env_int(name,default):
    try:return int(os.getenv(name,default))
    except Exception:return default

MAX_EMAIL_BYTES=env_int("MAX_EMAIL_MB",15)*1024*1024

@app.get("/")
def root():
    return {"name":"Email & Link Threat Analyzer","version":"0.6.0","docs":"/docs","health":"/health"}

@app.get("/health")
def health():
    from .yara_scan import yara, RULE_FILE
    return {"status":"ok","version":"0.6.0","yara":yara is not None,"yara_rules":RULE_FILE.exists()}

@app.post("/analyze")
async def analyze_email(file: UploadFile=File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(400,"Upload an .eml email file.")
    data=await file.read()
    if len(data)>MAX_EMAIL_BYTES:
        raise HTTPException(413,f"Email exceeds {MAX_EMAIL_BYTES//(1024*1024)} MB limit.")
    quarantine=None
    try:
        with tempfile.NamedTemporaryFile("wb",prefix="email_",suffix=".eml",dir=BASE_DIR/"storage/quarantine",delete=False) as tmp:
            tmp.write(data); quarantine=Path(tmp.name)
        logger.info("Email received filename=%s size=%d",file.filename,len(data))
        result=analyze(data)
        logger.info("Analysis complete filename=%s risk=%s score=%s",file.filename,result["risk_level"],result["risk_score"])
        return result
    except Exception as exc:
        logger.exception("Analysis failed filename=%s",file.filename)
        raise HTTPException(500,f"Analysis failed: {type(exc).__name__}")
    finally:
        if quarantine:
            quarantine.unlink(missing_ok=True)


# Gmail OAuth (read-only). Keep credentials.json and token.json in the project root;
# never expose either file to frontend JavaScript or commit them to source control.
GMAIL_CREDENTIALS = BASE_DIR / "credentials.json"
GMAIL_TOKEN = BASE_DIR / "token.json"
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
GMAIL_REDIRECT_URI = os.getenv(
    "GMAIL_REDIRECT_URI", "http://127.0.0.1:8000/auth/gmail/callback"
)
_oauth_states = {}

def _gmail_libs():
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import Flow
        from googleapiclient.discovery import build
        from google.auth.transport.requests import Request
        return Credentials, Flow, build, Request
    except ImportError as exc:
        raise HTTPException(
            500,
            "Gmail integration packages missing. Install: "
            "pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib"
        ) from exc

def _gmail_flow(state=None):
    _, Flow, _, _ = _gmail_libs()
    if not GMAIL_CREDENTIALS.exists():
        raise HTTPException(400, "credentials.json is missing from the project root.")
    try:
        flow = Flow.from_client_secrets_file(
            str(GMAIL_CREDENTIALS),
            scopes=GMAIL_SCOPES,
            redirect_uri=GMAIL_REDIRECT_URI,
            state=state,
        )
        return flow
    except Exception as exc:
        logger.exception("Unable to initialize Gmail OAuth")
        raise HTTPException(500, "Could not load Google OAuth client configuration.") from exc

def _gmail_service():
    Credentials, _, build, Request = _gmail_libs()
    if not GMAIL_TOKEN.exists():
        raise HTTPException(401, "Gmail is not connected. Click Connect Gmail first.")
    try:
        creds = Credentials.from_authorized_user_file(str(GMAIL_TOKEN), GMAIL_SCOPES)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            GMAIL_TOKEN.write_text(creds.to_json(), encoding="utf-8")
            try:
                GMAIL_TOKEN.chmod(0o600)
            except OSError:
                pass
        if not creds.valid:
            raise HTTPException(401, "Gmail authorization expired. Reconnect Gmail.")
        return build("gmail", "v1", credentials=creds, cache_discovery=False)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Gmail token could not be loaded/refreshed")
        raise HTTPException(401, "Gmail authorization failed. Reconnect Gmail.") from exc


@app.get("/auth/gmail/start")
def gmail_oauth_start():
    import secrets, time

    state = secrets.token_urlsafe(32)
    flow = _gmail_flow(state=state)

    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        code_challenge_method="S256",
    )

    # Prune expired states and cap outstanding states to limit unbounded growth.
    for old_state, value in list(_oauth_states.items()):
        if value.get("expires", 0) < time.time():
            _oauth_states.pop(old_state, None)
    while len(_oauth_states) >= 100:
        _oauth_states.pop(next(iter(_oauth_states)))
    _oauth_states[state] = {
        "expires": time.time() + 600,
        "code_verifier": flow.code_verifier,
    }

    return {"authorization_url": authorization_url}

@app.get("/auth/gmail/callback")
def gmail_oauth_callback(code: str = "", state: str = "", error: str = ""):
    import time

    if error:
        raise HTTPException(
            400,
            f"Google authorization was not completed: {error}"
        )

    saved_state = _oauth_states.pop(state, None)

    if not state or not saved_state:
        raise HTTPException(
            400,
            "OAuth state missing or expired. Start Connect Gmail again."
        )

    if saved_state["expires"] < time.time():
        raise HTTPException(
            400,
            "OAuth state expired. Start Connect Gmail again."
        )

    flow = _gmail_flow(state=state)
    flow.code_verifier = saved_state["code_verifier"]

    try:
        flow.fetch_token(code=code)

        creds = flow.credentials
        GMAIL_TOKEN.write_text(creds.to_json(), encoding="utf-8")
        try:
            GMAIL_TOKEN.chmod(0o600)
        except OSError:
            pass  # Windows ACLs govern access on Windows.

        logger.info("Gmail OAuth authorization completed")

        return {
            "status": "connected",
            "message": "Gmail connected. You may return to the analyzer."
        }

    except Exception as exc:
        # Avoid printing OAuth internals or potentially sensitive provider responses.
        logger.error("Gmail OAuth callback failed (%s)", type(exc).__name__)

        raise HTTPException(
            status_code=400,
            detail=f"Google token exchange failed: {type(exc).__name__}"
        ) from exc

@app.get("/auth/gmail/status")
def gmail_oauth_status():
    return {"connected": GMAIL_TOKEN.exists()}

@app.post("/auth/gmail/disconnect")
def gmail_oauth_disconnect():
    GMAIL_TOKEN.unlink(missing_ok=True)
    return {"connected": False}

@app.get("/gmail/messages")
def gmail_list_messages(max_results: int = 20, page_token: str = ""):
    if max_results < 1 or max_results > 50:
        raise HTTPException(400, "max_results must be between 1 and 50.")
    service = _gmail_service()
    try:
        args = {"userId": "me", "maxResults": max_results}
        if page_token:
            args["pageToken"] = page_token
        listing = service.users().messages().list(**args).execute()
        messages = []
        for item in listing.get("messages", []):
            msg = service.users().messages().get(
                userId="me", id=item["id"], format="metadata",
                metadataHeaders=["From", "To", "Subject", "Date"]
            ).execute()
            headers = {
                h["name"].lower(): h["value"]
                for h in msg.get("payload", {}).get("headers", [])
            }
            messages.append({
                "id": msg["id"],
                "threadId": msg.get("threadId", ""),
                "from": headers.get("from", ""),
                "to": headers.get("to", ""),
                "subject": headers.get("subject", "(no subject)"),
                "date": headers.get("date", ""),
                "snippet": msg.get("snippet", ""),
            })
        return {"messages": messages, "nextPageToken": listing.get("nextPageToken")}
    except Exception as exc:
        logger.exception("Gmail message listing failed")
        raise HTTPException(502, "Could not fetch Gmail messages.") from exc

@app.post("/gmail/messages/{message_id}/analyze")
def gmail_analyze_message(message_id: str):
    import base64
    service = _gmail_service()
    try:
        msg = service.users().messages().get(
            userId="me", id=message_id, format="raw"
        ).execute()
        raw = base64.urlsafe_b64decode(msg["raw"] + "===")
        if len(raw) > MAX_EMAIL_BYTES:
            raise HTTPException(
                413, f"Email exceeds {MAX_EMAIL_BYTES // (1024*1024)} MB limit."
            )
        result = analyze(raw)
        result["source"] = "gmail"
        result["gmail_message_id"] = message_id
        logger.info("Gmail message analyzed id=%s risk=%s", message_id, result.get("risk_level"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Gmail message analysis failed id=%s", message_id)
        raise HTTPException(502, "Could not retrieve or analyze this Gmail message.") from exc

@app.get("/version")
def version():
    return {"version":"0.6.0","features":["parsing","authentication","received-chain","url-analysis","reputation","yara","pdf","office","archive-static-analysis","gmail-oauth-readonly"]}
