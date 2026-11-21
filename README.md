# Phishing URL & Email Analyzer

A high-performance cybersecurity intelligence platform and Chrome Extension (Manifest V3) for identifying phishing campaigns, deceptive lookalike domains, brand typosquatting, TLS certificate anomalies, and email header spoofing in real-time.

---

## Architecture Overview

```
phishing-analyzer/
├── backend/
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── url_analyzer.py       # Heuristics, WHOIS, Homograph/IDN, TLS cert, VirusTotal v3
│   │   └── email_analyzer.py     # RFC 822 parser, From/Reply-To/Return-Path mismatches, SPF/DKIM/DMARC DNS
│   ├── .env.example              # Template environment configuration
│   ├── .env                      # Local environment configuration
│   ├── cache.db                  # SQLite database for threat intelligence TTL caching
│   ├── main.py                   # FastAPI application, CORS middleware, web dashboard & endpoints
│   ├── models.py                 # Pydantic v2 data models & request/response schemas
│   ├── requirements.txt          # Python dependencies
│   └── scoring.py                # Deterministic 0–100 weighted risk scoring engine
├── extension/
│   ├── manifest.json             # Chrome Manifest V3 configuration
│   ├── background.js             # Service worker, URL batching, local caching
│   ├── content.js                # DOM link extraction, visible page scanner, on-page highlight
│   ├── popup.html                # Cyber defense dark-mode popup interface
│   ├── popup.css                 # Responsive popup styling
│   ├── popup.js                  # Extension logic, active tab scan, email tester, history
│   └── icons/                    # Extension icons (16px, 48px, 128px)
├── tests/
│   └── test_analyzer.py          # Unit, integration, heuristic, and endpoint tests
└── README.md                     # Documentation, setup guide, and edge-case reference
```

---

## Key Features

### 1. URL Analysis Engine (`backend/analyzers/url_analyzer.py`)
- **Domain Decomposition**: Uses `tldextract` to separate subdomains, registrable domain, and public suffixes (avoiding public suffix traps like `co.uk` or `github.io`).
- **Domain Age Inspection**: Resilient WHOIS queries with timeout handling, multi-date parsing (ISO strings, `datetime` lists), flagging domains registered `< 30 days` ago.
- **Homograph & Punycode Detection**: Detects Internationalized Domain Names (`xn--` prefix) and mixed-script unicode glyph spoofing using `idna`.
- **Brand Typosquatting / Levenshtein**: Checks candidate domains against 40+ high-value targets (PayPal, Google, Apple, Microsoft, Chase, Bank of America, Binance, etc.) using Levenshtein distance and optical leetspeak substitution (`0` -> `o`, `1` -> `l`, `rn` -> `m`, `vv` -> `w`).
- **TLS/SSL Certificate Inspection**: Validates port 443 certificates with a 3-second timeout, extracting validity, issuer, Subject Alternative Names (SAN), and days until expiration.
- **VirusTotal Threat Intelligence**: Integrates with VirusTotal v3 API using `httpx.AsyncClient` with a two-tier cache (in-memory L1 + SQLite L2) governed by `CACHE_TTL_SECONDS`. Works offline with heuristic fallbacks if no API key is provided.

### 2. Email Header Authentication (`backend/analyzers/email_analyzer.py`)
- **RFC 822/5322 Parsing**: Parses raw `.eml` files or pasted email headers.
- **Identity Mismatch Detection**:
  - `From` domain vs `Reply-To` domain mismatch (diverted response attacks).
  - `From` domain vs `Return-Path` envelope sender mismatch.
  - Display name brand impersonation (e.g. `"PayPal Security" <alert@random-domain.xyz>`).
  - Embedded email addresses inside display names (e.g. `"security@paypal.com" <scammer@attacker.top>`).
- **Authentication Header Verification**: Parses `Authentication-Results` and `Received-SPF` headers.
- **DNS Record Verification**: Queries live DNS `TXT` records using `dnspython` for SPF (`v=spf1`), DMARC (`_dmarc.<domain>`), and DKIM (`<selector>._domainkey.<domain>` with `default` fallback).
- **Embedded Link Correlation**: Extracts URLs from email bodies and analyzes them through the URL analyzer.

### 3. Weighted Risk Scoring Engine (`backend/scoring.py`)
Deterministic score (`0–100`) mapped to:
- **Low Risk** (`0–29`): Normal, verified, authentic indicators.
- **Suspicious** (`30–69`): Missing security controls, newly registered domains, or slight anomalies.
- **High Risk** (`70–100`): Active threat intelligence hits, Punycode homographs, brand typosquatting, or failed DMARC with spoofed headers.
- Generates clear, human-readable explanations detailing why each score component was triggered.

### 4. Chrome Extension (Manifest V3)
- **Active Tab Scanner**: Automatically evaluates the domain security of the currently visited site.
- **Page Links Scanner**: Extracts visible hyperlinks, batch-analyzes them via the backend, and highlights malicious/suspicious links directly on the webpage with dashed red outlines.
- **Quick Email Header Inspector**: Allows testing suspicious email headers directly inside the popup with a sample loader.
- **Scan History**: Displays recent scans cached locally and synchronized with the backend.

### 5. Web Dashboard
FastAPI serves an interactive web dashboard on `GET /` (`http://127.0.0.1:8000/`) allowing testing directly from any web browser without needing the extension installed.

---

## Local Development & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.10 – 3.15)
- Google Chrome or Chromium-based browser (Edge, Brave)

### 1. Create Virtual Environment & Install Dependencies
Open PowerShell or terminal in the project directory:

```powershell
cd phishing-analyzer/backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1
# (On macOS/Linux: source .venv/bin/activate)

# Install requirements
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env`:

```powershell
cp .env.example .env
```

Edit `.env` (optional):
```ini
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
CACHE_TTL_SECONDS=3600
PORT=8000
HOST=127.0.0.1
```
> **Note**: If `VIRUSTOTAL_API_KEY` is omitted, the analyzer runs in heuristic mode without external API dependency.

### 3. Start the Backend API Server
```powershell
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

- **Web Dashboard**: Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.
- **Interactive OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## Loading the Chrome Extension

1. Open Google Chrome and navigate to `chrome://extensions`.
2. Toggle **Developer mode** on (top-right corner).
3. Click **Load unpacked** (top-left).
4. Select the `phishing-analyzer/extension/` folder.
5. The **PhishAnalyzer** shield icon will appear in your Chrome toolbar.
6. Click the extension icon to view real-time analysis of the current tab or test email headers.

---

## Running Automated Tests

Run the complete test suite with `pytest`:

```powershell
cd phishing-analyzer
.\backend\.venv\Scripts\python.exe -m pytest tests/test_analyzer.py -v
```

Tests cover:
- URL parsing with tldextract and IPv4 detection
- Benign domain reputation (`github.com`, `wikipedia.org`)
- IDN / Punycode homographs (`xn--gogle-pra.com`)
- Optical leet and Levenshtein typosquatting (`paypa1.com`, `rnicrosoft.com`)
- Domain age WHOIS parsing and error tolerances
- Email header mismatch detection (`From` vs `Reply-To` vs `Return-Path`)
- Display name impersonation spoof detection
- Authentication-Results token parsing (SPF, DKIM, DMARC)
- Deterministic 0–100 scoring engine calculations
- FastAPI endpoints (`/health`, `/analyze/url`, `/analyze/url/batch`, `/analyze/email`, `/recent`, `/`)

---

## Edge-Case Handling & Production Considerations

### 1. CDNs and Anycast IP Addresses
- **Observation**: Many sites use Cloudflare, Fastly, AWS CloudFront, or Akamai. These services route thousands of domains through shared IP addresses and use multi-domain Subject Alternative Names (SAN) certificates.
- **Mitigation**: The analyzer validates certificates by matching against the certificate's SAN list rather than just common name (CN). It only flags IP hosts when the user enters an IP address directly as the target URL host, avoiding false positives on CDN-backed domains.

### 2. URL Shorteners & Redirect Chains
- **Observation**: Attackers frequently hide malicious domains behind shorteners like `bit.ly`, `tinyurl.com`, or `t.co`.
- **Mitigation**: The analyzer flags embedded redirect parameters (e.g. `?url=`, `//` in paths, `@` authentication notation). In enterprise deployments, an HTTP HEAD request with redirect-following (`httpx.get(..., follow_redirects=True)`) traces hops to the final landing destination.

### 3. Multi-Level Subdomains & Free Dynamic DNS
- **Observation**: Phishing often uses free providers like `example.duckdns.org` or `account-login.pages.dev`.
- **Mitigation**: Using `tldextract` ensures that the Public Suffix List (PSL) correctly identifies `duckdns.org` or `pages.dev` as public suffixes, so the registered domain becomes `example.duckdns.org`. Furthermore, excessive subdomains (>= 3 parts) are penalized with `EXCESSIVE_SUBDOMAINS`.

### 4. DMARC Alignment & Email Forwarding
- **Observation**: Legitimate mailing lists or auto-forwarders break SPF because the forwarding server's IP is not in the original sender's SPF record.
- **Mitigation**: The scoring engine evaluates SPF, DKIM, and DMARC in combination. If DKIM passes with valid cryptographic signature, DMARC can still align and pass even if SPF softfails. Conversely, strict `p=reject` policies where both fail trigger an immediate High Risk score.

### 5. WHOIS Privacy & ccTLD Formatting Discrepancies
- **Observation**: Some registrars mask creation dates or use registrar privacy services (e.g., Withheld for Privacy, Domains By Proxy). Different ccTLDs (like `.de` or `.jp`) do not provide uniform creation dates.
- **Mitigation**: The WHOIS analyzer handles `None`, ISO datetime strings, single datetimes, and lists of datetimes. If WHOIS information is missing, the system does not crash or falsely flag the domain; it documents the absence and relies on TLS, DNS, homograph, and heuristic signals.

### 6. VirusTotal API Quotas & Rate Limits
- **Observation**: Public VirusTotal API keys are limited to 4 requests per minute and 500 requests per day.
- **Mitigation**: A two-tier caching architecture (in-memory dictionary for sub-second repeat lookups and SQLite database with timestamp-based TTL) ensures duplicate domains are not re-queried within `CACHE_TTL_SECONDS` (default: 1 hour).
