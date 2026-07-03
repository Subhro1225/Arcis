# Arcis — ML Phishing URL Detector

Arcis is a real-time, explainable phishing URL detection system built using a pre-trained and tuned **LightGBM** classifier. It features a local REST API backend, a premium glassmorphic web dashboard, and a Manifest V3 Google Chrome extension.

## Features

- **Lexical Parsing**: Analyzes character ratios, length metrics, path segments, and parameter structures.
- **Live DNS & Network Reputation**: Resolves active IPs, MX servers, Nameservers, and connection response latency.
- **Autonomous IP-to-ASN Translation**: Executes local DNS TXT lookups against the Cymru DNS network to resolve Autonomous System Numbers (ASN) with zero HTTP API overhead.
- **Domain Registry Age Verification**: Queries WHOIS records to check the domain registration creation age and days remaining until expiration.
- **Local Explainability**: Computes directional feature contributions to show why a link was flagged.

---

## Repository Structure

```
Arcis/
├── backend/
│   ├── app.py                      # Flask REST API server
│   ├── models/                     # Saved ML model binaries
│   │   └── url_phishing_bundle.joblib
│   └── services/                   # Feature extraction & classification services
│       ├── url_classifier.py       # URL feature extraction & LightGBM model logic
│       └── email_classifier.py     # Email classification template (for your model)
├── frontend/
│   ├── index.html                  # Premium SaaS Dashboard
│   ├── style.css                   # Glassmorphic style sheet
│   └── app.js                      # Web app integration logic
├── extension/                      # Manifest V3 Chrome Extension
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   └── background.js
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Installation & Setup

### Prerequisites
- **Python 3.11** or **Python 3.10**
- Google Chrome (or any Chromium-based browser)

### 1. Initialize Virtual Environment & Install Dependencies
Run the following commands in your workspace:

```bash
# Create a virtual environment
python3.11 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 2. Run the Backend API Server

**For Development:**
```bash
python backend/app.py
```

**For Production (High Concurrency & Load):**
Use Gunicorn with multi-worker threads to handle a high volume of users concurrently:
```bash
gunicorn -w 4 -b 0.0.0.0:5001 --chdir backend app:app
```
The API server exposes:
- `/api/analyze/url` (`POST`) for URL phishing scans.
- `/api/analyze/email` (`POST`) for email sender security checks.

### 3. Open the Web Application
Open the [index.html](file:///Users/Anurag/Anurag/Projects/Arcis/frontend/index.html) file inside the `frontend/` folder directly in any browser.

### 4. Load the Chrome Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the `extension` folder inside this directory.
5. Pin the **Arcis Phishing Detector** extension, navigate to any site, and click the shield icon to analyze the page in one click.
