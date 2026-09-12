# ThreatTrace — SIH 2026 MVP Prototype

A defensive demonstration prototype for the proposed **AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**.

## What this prototype demonstrates

1. Raw email ingestion
2. Header parsing
3. SPF / DKIM / DMARC result inspection
4. Reply-To / From anomaly detection
5. Social-engineering cue detection
6. URL and IP extraction
7. Relay-path reconstruction from `Received` headers
8. Demonstration IP / infrastructure intelligence
9. Risk score and verdict
10. Analyst-facing forensic case summary

## Important prototype limitations

- The current score is a **demonstration heuristic**, not a validated ML model.
- IP locations are intentionally **static demo data** so the prototype works without external API keys.
- Infrastructure geolocation must never be presented as proof of an attacker's physical location.
- Production deployment should use approved threat-intelligence/GeoIP providers, a validated dataset, authentication, access controls, secure evidence storage, and privacy/retention controls.

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`

Click **Load Demo Email**, then **Analyze Email**.

## Suggested SIH demo flow

1. Load the demo email.
2. Show the HIGH RISK score.
3. Point to SPF/DKIM/DMARC failures.
4. Show the Reply-To mismatch.
5. Show the relay hops.
6. Show extracted IP infrastructure.
7. Copy the forensic case summary.
8. Explain that the production version will replace demo intelligence with approved providers and add a trained NLP/ML classifier + graph correlation engine.
