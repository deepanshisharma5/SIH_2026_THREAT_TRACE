from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
app = FastAPI(title="ThreatTrace Prototype", version="0.1")

app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

SUSPICIOUS_TERMS = [
    "urgent", "verify", "password", "account suspended", "invoice",
    "payment", "gift card", "wire transfer", "click immediately",
    "confirm your account", "login", "credential"
]

DEMO_IP_INTEL = {
    "185.199.108.153": {"country":"United States", "region":"Virginia", "city":"Ashburn", "asn":"AS54113", "provider":"Cloud infrastructure", "risk":"medium"},
    "203.0.113.10": {"country":"Example", "region":"Demo", "city":"Demo City", "asn":"AS64500", "provider":"Demo ISP", "risk":"high"},
    "198.51.100.24": {"country":"Example", "region":"Demo", "city":"Demo City", "asn":"AS64501", "provider":"Demo Hosting", "risk":"high"},
}

def extract_ips(text):
    return list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))

def extract_urls(text):
    urls = re.findall(r"https?://[^\s<>\"]+", text)
    return list(dict.fromkeys([u.rstrip(".,);]") for u in urls]))

def parse_email(raw):
    msg = Parser(policy=policy.default).parsestr(raw)
    headers = {k: str(v) for k, v in msg.items()}
    body = msg.get_body(preferencelist=("plain", "html"))
    body_text = body.get_content() if body else ""
    received = msg.get_all("Received", [])
    ips = extract_ips("\n".join(map(str, received)))
    urls = extract_urls(body_text)
    return headers, body_text, list(map(str, received)), ips, urls

def analyze(raw):
    headers, body, received, ips, urls = parse_email(raw)
    lower = (raw + "\n" + body).lower()

    score = 0
    signals = []

    auth = headers.get("Authentication-Results", "").lower()
    if "spf=fail" in auth:
        score += 25; signals.append(("SPF failure", "high"))
    elif "spf=pass" in auth:
        signals.append(("SPF pass", "low"))

    if "dkim=fail" in auth:
        score += 20; signals.append(("DKIM failure", "high"))
    elif "dkim=pass" in auth:
        signals.append(("DKIM pass", "low"))

    if "dmarc=fail" in auth:
        score += 25; signals.append(("DMARC failure", "high"))
    elif "dmarc=pass" in auth:
        signals.append(("DMARC pass", "low"))

    sender = headers.get("From", "").lower()
    reply = headers.get("Reply-To", "").lower()
    if reply and reply != sender:
        score += 15; signals.append(("Reply-To differs from From", "medium"))

    term_hits = [t for t in SUSPICIOUS_TERMS if t in lower]
    if term_hits:
        score += min(20, len(term_hits) * 4)
        signals.append((f"Social-engineering cues ({len(term_hits)})", "medium"))

    for u in urls:
        host = urlparse(u).hostname or ""
        if re.search(r"\d+\.\d+\.\d+\.\d+", host):
            score += 15; signals.append(("URL uses raw IP address", "high"))
        if any(x in host for x in ["bit.ly", "tinyurl.com", "t.co"]):
            score += 8; signals.append(("URL shortener detected", "medium"))

    if len(received) >= 3:
        score += 8; signals.append(("Multi-hop relay chain", "medium"))

    score = min(score, 100)
    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"

    trace = []
    for idx, hop in enumerate(received):
        hop_ips = extract_ips(hop)
        trace.append({"hop": idx+1, "header": hop, "ips": hop_ips})

    intel = []
    for ip in ips:
        info = DEMO_IP_INTEL.get(ip, {
            "country":"Unknown", "region":"Unknown", "city":"Unknown",
            "asn":"Unknown", "provider":"Unknown", "risk":"unknown"
        })
        intel.append({"ip": ip, **info})

    return {
        "verdict": verdict,
        "risk_score": score,
        "signals": [{"name":n, "severity":s} for n,s in signals],
        "sender": headers.get("From",""),
        "reply_to": headers.get("Reply-To",""),
        "subject": headers.get("Subject",""),
        "authentication": headers.get("Authentication-Results",""),
        "urls": urls,
        "ips": ips,
        "relay_hops": trace,
        "ip_intelligence": intel,
        "limitations": [
            "Geolocation is infrastructure/IP geolocation, not proof of an attacker's physical location.",
            "Demo IP intelligence is intentionally local/static; production should connect to approved threat-intelligence providers.",
            "The prototype score is a demonstration heuristic, not a validated production ML model."
        ]
    }

@app.get("/", response_class=HTMLResponse)
async def home():
    return (BASE / "static" / "index.html").read_text(encoding="utf-8")

@app.post("/analyze")
async def analyze_endpoint(request: Request):
    data = await request.json()
    raw = data.get("email", "")
    if not raw.strip():
        return JSONResponse({"error":"Paste a raw email first."}, status_code=400)
    return JSONResponse(analyze(raw))
