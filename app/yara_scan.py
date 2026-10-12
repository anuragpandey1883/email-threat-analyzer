from pathlib import Path

try:
    import yara
except ImportError:
    yara = None

RULE_DIR = Path(__file__).resolve().parent.parent / "yara_rules"
RULE_FILE = RULE_DIR / "email_analyzer.yar"

def scan_bytes(data: bytes):
    if yara is None or not RULE_FILE.exists():
        return []
    try:
        rules = yara.compile(filepath=str(RULE_FILE))
        matches = rules.match(data=data)
        return [{"rule": m.rule, "tags": list(m.tags)} for m in matches]
    except Exception:
        return []
