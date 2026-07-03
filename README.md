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
├── app.py                      # Flask REST API server
├── model_service.py            # Feature extraction & classification pipeline
├── phishing_model_bundle.joblib # Trained LightGBM model & scaler bundle
├── index.html                  # Web application UI
├── style.css                   # Premium CSS styles
├── frontend.js                 # Frontend API integration script
├── extension/                  # Chrome extension directory
│   ├── manifest.json           # Extension manifest V3 config
│   ├── popup.html              # Extension popup layout
│   ├── popup.css               # Extension styles
│   └── popup.js                # Extension logic
└── .gitignore                  # Git exclude list
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
pip install joblib lightgbm scipy numpy scikit-learn flask flask-cors pandas tldextract dnspython python-whois
```

### 2. Run the Backend API Server
Start the Flask backend server:
```bash
python app.py
```
The API server will run at `http://localhost:5001/api/analyze`.

### 3. Open the Web Application
Simply open the `index.html` file in any modern web browser to use the graphical web application dashboard. Paste a URL and click **Analyze Link** to get instant classification metrics and indicators.

### 4. Load the Chrome Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the `extension` folder inside this directory.
5. Pin the **Arcis Phishing Detector** extension, navigate to any site, and click the shield icon to analyze the page in one click.
