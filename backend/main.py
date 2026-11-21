"""
Phishing URL & Email Analyzer - FastAPI Backend.
Provides:
- GET / : Lightweight, interactive web dashboard
- GET /health : System health and configuration check
- POST /analyze/url : Analyze single URL or domain
- POST /analyze/url/batch : Batch analyze multiple URLs
- POST /analyze/email : Analyze email headers or .eml content
- GET /recent : Retrieve recent scans history
"""

import os
import uuid
import datetime
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv

from models import (
    URLAnalysisRequest,
    BatchURLAnalysisRequest,
    URLAnalysisResult,
    BatchURLAnalysisResult,
    EmailAnalysisRequest,
    EmailAnalysisResult,
    RecentScanItem,
    HealthResponse,
    RiskLevel,
)
from analyzers.url_analyzer import analyze_url, VIRUSTOTAL_API_KEY, CACHE_TTL_SECONDS
from analyzers.email_analyzer import analyze_email_content

load_dotenv()

app = FastAPI(
    title="Phishing URL & Email Analyzer API",
    description="Cybersecurity API for detecting phishing URLs, homograph domains, typo impersonations, and spoofed email headers.",
    version="1.0.0",
)

# CORS configuration allowing Chrome extensions and local frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for recent scans (last 50 items)
RECENT_SCANS: List[RecentScanItem] = []


def record_recent_scan(scan_type: str, target: str, score: int, level: RiskLevel, reasons: List[str]):
    """Record scan in history."""
    item = RecentScanItem(
        id=str(uuid.uuid4())[:8],
        type=scan_type,
        target=target,
        risk_score=score,
        risk_level=level,
        reasons=reasons[:5],
        timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    RECENT_SCANS.insert(0, item)
    if len(RECENT_SCANS) > 50:
        RECENT_SCANS.pop()


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint displaying system and threat intel status."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        virustotal_configured=bool(VIRUSTOTAL_API_KEY),
        cache_ttl_seconds=CACHE_TTL_SECONDS,
    )


@app.post("/analyze/url", response_model=URLAnalysisResult)
async def endpoint_analyze_url(request: URLAnalysisRequest):
    """
    Analyze a URL or domain for:
    - Homograph, Punycode, and brand typosquatting
    - WHOIS domain creation age
    - TLS/SSL certificate validity and expiration
    - VirusTotal reputation (with TTL cache)
    - Structural heuristics
    """
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    result = await analyze_url(request.url.strip())
    record_recent_scan(
        scan_type="url",
        target=result.normalized_url,
        score=result.risk_score,
        level=result.risk_level,
        reasons=result.reasons,
    )
    return result


@app.post("/analyze/url/batch", response_model=BatchURLAnalysisResult)
async def endpoint_batch_analyze_url(request: BatchURLAnalysisRequest):
    """
    Batch analyze a list of URLs (used by Chrome Extension content script).
    """
    if not request.urls:
        return BatchURLAnalysisResult(results=[], total=0)

    # Process up to 50 URLs in one batch
    targets = [u.strip() for u in request.urls[:50] if u.strip()]
    results: List[URLAnalysisResult] = []

    for target in targets:
        try:
            res = await analyze_url(target)
            results.append(res)
            record_recent_scan(
                scan_type="url",
                target=res.normalized_url,
                score=res.risk_score,
                level=res.risk_level,
                reasons=res.reasons,
            )
        except Exception as e:
            # Continue processing others on individual failure
            pass

    return BatchURLAnalysisResult(results=results, total=len(results))


@app.post("/analyze/email", response_model=EmailAnalysisResult)
async def endpoint_analyze_email(request: EmailAnalysisRequest):
    """
    Analyze raw RFC 822 email headers or .eml content for:
    - From vs Reply-To vs Return-Path mismatches
    - Display name brand impersonation
    - SPF, DKIM, and DMARC verification via headers and DNS TXT records
    - Embedded URLs risk evaluation
    """
    if not request.raw_content or not request.raw_content.strip():
        raise HTTPException(status_code=400, detail="Email content/headers cannot be empty")

    result = await analyze_email_content(request.raw_content)
    target_summary = result.subject or result.mismatch.from_header or "Pasted Email"
    record_recent_scan(
        scan_type="email",
        target=target_summary[:60],
        score=result.risk_score,
        level=result.risk_level,
        reasons=result.reasons,
    )
    return result


@app.get("/recent", response_model=List[RecentScanItem])
async def endpoint_recent_scans():
    """Retrieve recent scan activity for the web dashboard and extension popup."""
    return RECENT_SCANS


@app.get("/", response_class=HTMLResponse)
async def web_dashboard():
    """Serve the ultra-modern cybersecurity console dashboard."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PhishAnalyzer • Threat Intelligence Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #06090f;
      --bg-surface: #0c121e;
      --bg-card: #121a2b;
      --bg-card-sub: #172238;
      --border: #1e2d47;
      --border-focus: #3b82f6;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --primary: #3b82f6;
      --primary-glow: rgba(59, 130, 246, 0.25);
      --primary-hover: #2563eb;
      --safe: #10b981;
      --safe-bg: rgba(16, 185, 129, 0.1);
      --safe-border: rgba(16, 185, 129, 0.3);
      --suspicious: #f59e0b;
      --suspicious-bg: rgba(245, 158, 11, 0.1);
      --suspicious-border: rgba(245, 158, 11, 0.3);
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.12);
      --danger-border: rgba(239, 68, 68, 0.35);
      --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      background-image: 
        radial-gradient(circle at 10% 20%, rgba(59, 130, 246, 0.14) 0%, transparent 45%),
        radial-gradient(circle at 90% 80%, rgba(239, 68, 68, 0.10) 0%, transparent 45%),
        linear-gradient(rgba(30, 45, 71, 0.35) 1px, transparent 1px),
        linear-gradient(90deg, rgba(30, 45, 71, 0.35) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 48px 48px, 48px 48px;
      background-attachment: fixed;
      position: relative;
      overflow-x: hidden;
    }

    /* Fixed Background Cyber Phishing Poster Art */
    .bg-phish-poster {
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      pointer-events: none;
      z-index: 0;
      overflow: hidden;
      opacity: 0.16;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .bg-phish-poster svg {
      width: 110vw;
      max-width: 1400px;
      height: auto;
      filter: drop-shadow(0 0 40px rgba(59, 130, 246, 0.3));
    }

    .app-container {
      position: relative;
      z-index: 1;
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 24px 60px 24px;
    }

    /* Top Navigation Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 32px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .brand-icon {
      width: 44px;
      height: 44px;
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 20px rgba(37, 99, 235, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.15);
    }

    .brand-icon svg { width: 24px; height: 24px; fill: white; }

    .brand h1 {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand p {
      font-size: 13px;
      color: var(--text-muted);
    }

    .header-pills {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 6px 14px;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 100px;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
    }

    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--safe);
      box-shadow: 0 0 10px var(--safe);
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.85); }
    }

    /* Tabs */
    .tabs-nav {
      display: flex;
      background: var(--bg-surface);
      padding: 5px;
      border-radius: 12px;
      border: 1px solid var(--border);
      margin-bottom: 28px;
      gap: 4px;
    }

    .tab-trigger {
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 12px 18px;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .tab-trigger svg { width: 16px; height: 16px; stroke: currentColor; fill: none; }

    .tab-trigger:hover {
      color: var(--text);
      background: rgba(255, 255, 255, 0.04);
    }

    .tab-trigger.active {
      background: var(--primary);
      color: white;
      box-shadow: 0 4px 15px var(--primary-glow);
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.25s ease-out; }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Cards */
    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
      position: relative;
      overflow: hidden;
    }

    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; height: 1px;
      background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.3), transparent);
    }

    .card-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Inputs & Buttons */
    .search-bar {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
    }

    .input-wrapper {
      position: relative;
      flex: 1;
    }

    .input-wrapper svg {
      position: absolute;
      left: 14px;
      top: 50%;
      transform: translateY(-50%);
      width: 18px;
      height: 18px;
      stroke: var(--text-dim);
    }

    input[type="text"], textarea {
      width: 100%;
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 13px 16px 13px 44px;
      border-radius: 10px;
      font-size: 14px;
      font-family: var(--font-mono);
      transition: all 0.2s;
    }

    textarea {
      padding: 14px 16px;
      min-height: 150px;
      resize: vertical;
      font-size: 13px;
      line-height: 1.6;
    }

    input[type="text"]:focus, textarea:focus {
      outline: none;
      border-color: var(--border-focus);
      box-shadow: 0 0 0 3px var(--primary-glow);
      background: #141f33;
    }

    .btn-action {
      background: linear-gradient(135deg, var(--primary), var(--primary-hover));
      color: white;
      border: none;
      padding: 0 26px;
      border-radius: 10px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
      white-space: nowrap;
      box-shadow: 0 4px 14px var(--primary-glow);
    }

    .btn-action:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
    }

    .btn-action:active { transform: translateY(0); }

    /* Sample Pills */
    .sample-strip {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 13px;
      color: var(--text-muted);
    }

    .chip-btn {
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: #cbd5e1;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
      font-family: var(--font-mono);
      transition: all 0.15s;
    }

    .chip-btn:hover {
      background: var(--bg-card-sub);
      border-color: #3b82f6;
      color: white;
      transform: translateY(-1px);
    }

    /* Result Dashboard Presentation */
    .result-section {
      margin-top: 28px;
      display: none;
      border-top: 1px solid var(--border);
      padding-top: 28px;
      animation: fadeIn 0.3s ease-out;
    }

    /* Master Threat Gauge */
    .threat-banner {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 24px;
      align-items: center;
      padding: 22px 28px;
      border-radius: 14px;
      margin-bottom: 24px;
      border: 1px solid;
    }

    .threat-banner.low {
      background: var(--safe-bg);
      border-color: var(--safe-border);
      box-shadow: 0 4px 20px rgba(16, 185, 129, 0.08);
    }

    .threat-banner.suspicious {
      background: var(--suspicious-bg);
      border-color: var(--suspicious-border);
      box-shadow: 0 4px 20px rgba(245, 158, 11, 0.08);
    }

    .threat-banner.high {
      background: var(--danger-bg);
      border-color: var(--danger-border);
      box-shadow: 0 4px 25px rgba(239, 68, 68, 0.15);
    }

    /* Circular SVG Gauge */
    .gauge-wrapper {
      position: relative;
      width: 76px;
      height: 76px;
    }

    .gauge-wrapper svg {
      transform: rotate(-90deg);
      width: 76px;
      height: 76px;
    }

    .gauge-bg {
      fill: none;
      stroke: rgba(255, 255, 255, 0.08);
      stroke-width: 6;
    }

    .gauge-bar {
      fill: none;
      stroke-width: 6;
      stroke-linecap: round;
      stroke-dasharray: 200;
      transition: stroke-dashoffset 0.8s ease-out;
    }

    .gauge-val {
      position: absolute;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      font-size: 20px;
      font-weight: 800;
      font-family: var(--font-mono);
    }

    .threat-tag {
      display: inline-block;
      padding: 3px 12px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }

    .threat-tag.low { background: var(--safe); color: #022c22; }
    .threat-tag.suspicious { background: var(--suspicious); color: #451a03; }
    .threat-tag.high { background: var(--danger); color: white; }

    .threat-target {
      font-size: 17px;
      font-weight: 700;
      font-family: var(--font-mono);
      word-break: break-all;
    }

    /* Reasons List */
    .reasons-container {
      margin-bottom: 24px;
    }

    .reasons-title {
      font-size: 12px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 10px;
    }

    .reason-row {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 10px 14px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 8px;
      font-size: 13.5px;
    }

    .reason-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      margin-top: 7px;
      flex-shrink: 0;
    }

    .reason-dot.high { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
    .reason-dot.suspicious { background: var(--suspicious); }
    .reason-dot.low { background: var(--safe); }

    /* Inspection Metrics Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }

    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
      position: relative;
    }

    .metric-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }

    .metric-head h4 {
      font-size: 12px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .metric-pill {
      font-size: 10.5px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      font-family: var(--font-mono);
    }

    .metric-pill.success { background: rgba(16, 185, 129, 0.15); color: #34d399; }
    .metric-pill.warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
    .metric-pill.danger { background: rgba(239, 68, 68, 0.15); color: #f87171; }

    .metric-table {
      width: 100%;
      font-size: 12px;
      border-collapse: collapse;
    }

    .metric-table td {
      padding: 5px 0;
      vertical-align: top;
    }

    .metric-table td:first-child {
      color: var(--text-dim);
      width: 42%;
      font-weight: 500;
    }

    .metric-table td:last-child {
      color: var(--text);
      font-family: var(--font-mono);
      word-break: break-word;
    }

    /* History Table */
    .table-container {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 10px;
    }

    table.data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    table.data-table th, table.data-table td {
      padding: 12px 16px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    table.data-table th {
      background: var(--bg-card);
      color: var(--text-muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    table.data-table tr:last-child td { border-bottom: none; }
    table.data-table tr:hover td { background: rgba(255, 255, 255, 0.02); }

    /* Skeleton Loading */
    .loader {
      display: none;
      text-align: center;
      padding: 40px;
    }

    .spinner {
      width: 32px;
      height: 32px;
      border: 3px solid var(--border);
      border-top-color: var(--primary);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 12px auto;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    /* Phishing Poster Hero Showcase */
    .poster-hero {
      background: linear-gradient(135deg, rgba(18, 26, 43, 0.95), rgba(11, 17, 30, 0.95));
      border: 1px solid rgba(59, 130, 246, 0.3);
      border-radius: 16px;
      padding: 24px 28px;
      margin-bottom: 28px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    }

    .poster-hero::before {
      content: '';
      position: absolute;
      top: 0; right: 0; bottom: 0; width: 45%;
      background: radial-gradient(circle at 70% 50%, rgba(59, 130, 246, 0.15), transparent 70%);
      pointer-events: none;
    }

    .poster-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }

    .poster-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: #f87171;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      font-family: var(--font-mono);
    }

    .poster-title {
      font-size: 19px;
      font-weight: 800;
      letter-spacing: -0.01em;
      margin-bottom: 6px;
      background: linear-gradient(135deg, #ffffff, #93c5fd);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .poster-desc {
      font-size: 13px;
      color: var(--text-muted);
      max-width: 680px;
      line-height: 1.5;
    }

    .poster-vectors {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }

    .vector-box {
      background: rgba(15, 23, 42, 0.7);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 14px;
      display: flex;
      gap: 10px;
      align-items: flex-start;
      transition: all 0.2s;
    }

    .vector-box:hover {
      border-color: #3b82f6;
      background: rgba(23, 34, 56, 0.85);
      transform: translateY(-2px);
    }

    .vector-icon {
      font-size: 18px;
      background: rgba(59, 130, 246, 0.12);
      border-radius: 6px;
      padding: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .vector-name {
      font-size: 12px;
      font-weight: 700;
      color: #e2e8f0;
      margin-bottom: 2px;
    }

    .vector-detail {
      font-size: 11px;
      color: var(--text-dim);
      line-height: 1.35;
    }

    /* Fullscreen Background Interactive Cyber Particle Canvas */
    #cyber-canvas {
      position: fixed;
      top: 0; left: 0;
      width: 100vw; height: 100vh;
      pointer-events: none;
      z-index: 0;
      opacity: 0.45;
    }

    /* Models Architecture Grid & Modal */
    .models-grid-layout {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
      margin-top: 20px;
    }

    .model-arch-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 22px;
      position: relative;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      overflow: hidden;
    }

    .model-arch-card:hover {
      border-color: #3b82f6;
      box-shadow: 0 10px 30px rgba(59, 130, 246, 0.15);
      transform: translateY(-3px);
    }

    .model-arch-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; width: 4px; height: 100%;
      background: var(--primary);
    }

    .model-arch-card.danger::before { background: var(--danger); }
    .model-arch-card.warning::before { background: var(--suspicious); }
    .model-arch-card.safe::before { background: var(--safe); }

    .model-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }

    .model-icon-badge {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: rgba(59, 130, 246, 0.15);
      color: #93c5fd;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
    }

    .model-status-chip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 8px;
      border-radius: 100px;
      font-size: 10px;
      font-weight: 700;
      font-family: var(--font-mono);
      text-transform: uppercase;
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .model-name {
      font-size: 15px;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 4px;
    }

    .model-spec {
      font-size: 12px;
      color: var(--text-dim);
      font-family: var(--font-mono);
      margin-bottom: 12px;
    }

    .model-desc-text {
      font-size: 13px;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 16px;
    }

    .model-meta-box {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 12px;
      font-family: var(--font-mono);
    }

    .model-meta-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 4px;
    }

    .model-meta-row:last-child { margin-bottom: 0; }
    .model-meta-label { color: var(--text-dim); }
    .model-meta-val { color: #e2e8f0; font-weight: 600; }

    /* Modal Overlay */
    .modal-backdrop {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(4, 7, 15, 0.82);
      backdrop-filter: blur(10px);
      z-index: 99999;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
      animation: modalFadeIn 0.25s ease-out;
    }

    @keyframes modalFadeIn {
      from { opacity: 0; transform: scale(0.96); }
      to { opacity: 1; transform: scale(1); }
    }

    .modal-window {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 20px;
      max-width: 900px;
      width: 100%;
      max-height: 88vh;
      overflow-y: auto;
      padding: 32px;
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.8);
      position: relative;
    }

    .modal-close-btn {
      position: absolute;
      top: 24px;
      right: 24px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text-muted);
      width: 32px;
      height: 32px;
      border-radius: 8px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
    }

    .modal-close-btn:hover { color: white; border-color: var(--danger); }

    /* Footer */
    footer {
      margin-top: 48px;
      text-align: center;
      font-size: 12px;
      color: var(--text-dim);
      border-top: 1px solid var(--border);
      padding-top: 24px;
    }
  </style>
</head>
<body>
  <!-- Fullscreen Interactive Cyber Particle Matrix Canvas -->
  <canvas id="cyber-canvas"></canvas>

  <!-- Atmospheric Cyber Phishing Poster Background Art -->
  <div class="bg-phish-poster">
    <svg viewBox="0 0 1200 800" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="gradShield" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.3"/>
          <stop offset="100%" stop-color="#1d4ed8" stop-opacity="0.05"/>
        </linearGradient>
        <linearGradient id="gradHook" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#ef4444" stop-opacity="0.4"/>
          <stop offset="100%" stop-color="#f59e0b" stop-opacity="0.1"/>
        </linearGradient>
      </defs>

      <!-- Digital Target Rings -->
      <circle cx="600" cy="400" r="340" fill="none" stroke="#1e293b" stroke-width="1.5" stroke-dasharray="12 8"/>
      <circle cx="600" cy="400" r="260" fill="none" stroke="#2563eb" stroke-width="1" stroke-opacity="0.3"/>
      <circle cx="600" cy="400" r="180" fill="none" stroke="#38bdf8" stroke-width="1" stroke-dasharray="4 6" stroke-opacity="0.25"/>

      <!-- Giant Central Shield Watermark -->
      <path d="M 600,160 L 780,220 L 780,440 Q 780,580 600,640 Q 420,580 420,440 L 420,220 Z" fill="url(#gradShield)" stroke="#3b82f6" stroke-width="2.5" stroke-opacity="0.4"/>

      <!-- Phishing Hook Caught in Barrier -->
      <path d="M 520,280 C 520,380 680,380 680,480 C 680,540 630,570 580,560 C 540,550 530,510 540,480 L 525,485" fill="none" stroke="url(#gradHook)" stroke-width="5" stroke-linecap="round"/>
      <polygon points="525,470 545,485 520,495" fill="#ef4444" opacity="0.6"/>

      <!-- Crosshairs & Grid Coordinates -->
      <line x1="100" y1="400" x2="1100" y2="400" stroke="#1e293b" stroke-width="1" stroke-dasharray="8 8"/>
      <line x1="600" y1="50" x2="600" y2="750" stroke="#1e293b" stroke-width="1" stroke-dasharray="8 8"/>
      <text x="615" y="190" fill="#3b82f6" font-family="monospace" font-size="14" opacity="0.5">DEFENSE://FIREWALL_ACTIVE</text>
      <text x="615" y="625" fill="#ef4444" font-family="monospace" font-size="13" opacity="0.5">TARGET_INTERCEPT://HOOK_NEUTRALIZED</text>
      <text x="140" y="390" fill="#64748b" font-family="monospace" font-size="12" opacity="0.4">LAT: 0x7F000001 // SEC_LEVEL: MAX</text>
    </svg>
  </div>

  <div class="app-container">
    <!-- Header -->
    <header>
      <div class="brand">
        <div class="brand-icon">
          <svg viewBox="0 0 24 24"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5zm0 18c-3.75-1-6.5-4.8-6.5-9V8.3l6.5-3.6 6.5 3.6V11c0 4.2-2.75 8-6.5 9z"/></svg>
        </div>
        <div>
          <h1>PhishAnalyzer</h1>
          <p>Phishing URL & Email Analyzer • Threat Intelligence & Identity Authentication Suite</p>
        </div>
      </div>
      <div class="header-pills">
        <div class="pill">
          <span class="pulse-dot"></span>
          <span id="sys-status">Initializing...</span>
        </div>
      </div>
    </header>

    <!-- Phishing Defense Poster Spotlight Banner -->
    <section class="poster-hero">
      <div class="poster-header">
        <span class="poster-tag">⚠️ Phishing Defense Initiative</span>
        <button class="chip-btn" onclick="togglePosterDetails()" id="btn-toggle-poster">Hide Anatomy</button>
      </div>
      <h2 class="poster-title">Zero-Trust Threat Defense • Don't Take The Bait</h2>
      <p class="poster-desc">
        91% of enterprise cyber incidents originate from deceptive links and spoofed headers. PhishAnalyzer actively deconstructs incoming indicators across four primary attack vectors:
      </p>

      <div class="poster-vectors" id="poster-vectors-grid">
        <div class="vector-box">
          <div class="vector-icon">🎣</div>
          <div>
            <div class="vector-name">Optical Typosquatting</div>
            <div class="vector-detail">Character substitution (paypa1, rnicrosoft) designed to trick human visual perception.</div>
          </div>
        </div>
        <div class="vector-box">
          <div class="vector-icon">🎭</div>
          <div>
            <div class="vector-name">Punycode Homographs</div>
            <div class="vector-detail">Internationalized Cyrillic/Greek glyphs (xn--gogle) masquerading as authentic brands.</div>
          </div>
        </div>
        <div class="vector-box">
          <div class="vector-icon">📧</div>
          <div>
            <div class="vector-name">Diverted Response Routing</div>
            <div class="vector-detail">Silent From vs Reply-To address mismatches coupled with missing DMARC policies.</div>
          </div>
        </div>
        <div class="vector-box">
          <div class="vector-icon">⏳</div>
          <div>
            <div class="vector-name">Disposable Infrastructure</div>
            <div class="vector-detail">Fresh domains registered &lt; 30 days ago used for rapid hit-and-run campaigns.</div>
          </div>
        </div>
      </div>
    </section>

    <!-- Navigation Tabs -->
    <nav class="tabs-nav">
      <button class="tab-trigger active" onclick="activateTab('url-view', this)">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        URL & Domain Scanner
      </button>
      <button class="tab-trigger" onclick="activateTab('email-view', this)">
        <svg viewBox="0 0 24 24"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
        Email Header Inspector
      </button>
      <button class="tab-trigger" onclick="activateTab('history-view', this); fetchHistory();">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        Recent Activity
      </button>
    </nav>

    <!-- TAB 1: URL Scanner -->
    <main id="url-view" class="tab-content active">
      <div class="card">
        <div class="card-title">
          <span>Target URL or Domain Inspection</span>
        </div>
        <div class="search-bar">
          <div class="input-wrapper">
            <svg viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="url-target" placeholder="e.g. https://paypa1-security-update.xyz/login or github.com" onkeypress="if(event.key==='Enter') executeUrlScan();">
          </div>
          <button class="btn-action" onclick="executeUrlScan()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
            Analyze Target
          </button>
        </div>

        <div class="sample-strip">
          <span>Quick Benchmark Samples:</span>
          <button class="chip-btn" onclick="testUrl('https://github.com')">github.com (Benign)</button>
          <button class="chip-btn" onclick="testUrl('http://paypa1-security-verify.xyz/login')">paypa1 (Typo & TLD)</button>
          <button class="chip-btn" onclick="testUrl('https://xn--gogle-pra.com')">gögle.com (Punycode)</button>
          <button class="chip-btn" onclick="testUrl('http://192.168.1.100/account/login.php')">IP-as-Host</button>
        </div>

        <div id="url-loader" class="loader">
          <div class="spinner"></div>
          <p style="color:var(--text-muted); font-size:13px;">Analyzing domain heuristics, WHOIS lifecycle, TLS/SSL & threat intelligence...</p>
        </div>

        <div id="url-result" class="result-section"></div>
      </div>
    </main>

    <!-- TAB 2: Email Header Inspector -->
    <main id="email-view" class="tab-content">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
          <div class="card-title" style="margin-bottom:0;">
            <span>Raw Email Headers & RFC 822 .eml Block</span>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="chip-btn" onclick="loadSampleEmail('spoofed')">Load Spoofed Phish</button>
            <button class="chip-btn" onclick="loadSampleEmail('legit')">Load Authentic Email</button>
          </div>
        </div>
        
        <textarea id="email-target" placeholder="Paste headers (From, Reply-To, Return-Path, Authentication-Results, Received-SPF) here..."></textarea>
        
        <div style="margin-top:14px;">
          <button class="btn-action" onclick="executeEmailScan()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Audit Email Authentication
          </button>
        </div>

        <div id="email-loader" class="loader">
          <div class="spinner"></div>
          <p style="color:var(--text-muted); font-size:13px;">Verifying SPF/DKIM/DMARC DNS records & sender identity alignment...</p>
        </div>

        <div id="email-result" class="result-section"></div>
      </div>
    </main>

    <!-- TAB 3: History -->
    <main id="history-view" class="tab-content">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:18px;">
          <div class="card-title" style="margin-bottom:0;">Threat Intelligence Event Log</div>
          <button class="chip-btn" onclick="fetchHistory()">Refresh History</button>
        </div>

        <div class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Target Indicator</th>
                <th>Risk Score</th>
                <th>Verdict</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody id="history-body">
              <tr><td colspan="5" style="text-align:center; color:var(--text-dim);">No scans logged yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </main>

    <!-- Footer -->
    <footer>
      PhishAnalyzer Engine v1.0.0 • Multi-Layered Heuristic & Threat Intelligence Defense
    </footer>
  </div>

  <script>
    function activateTab(tabId, el) {
      document.querySelectorAll('.tab-trigger').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      el.classList.add('active');
      document.getElementById(tabId).classList.add('active');
    }

    function testUrl(url) {
      document.getElementById('url-target').value = url;
      executeUrlScan();
    }

    async function executeUrlScan() {
      const url = document.getElementById('url-target').value.trim();
      if (!url) return;

      const loader = document.getElementById('url-loader');
      const container = document.getElementById('url-result');
      loader.style.display = 'block';
      container.style.display = 'none';

      try {
        const resp = await fetch('/analyze/url', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ url })
        });
        const data = await resp.json();
        renderUrlDashboard(data);
      } catch (err) {
        container.style.display = 'block';
        container.innerHTML = `<div style="color:var(--danger); padding:16px;">Failed to analyze URL: ${err.message}</div>`;
      } finally {
        loader.style.display = 'none';
      }
    }

    function renderUrlDashboard(data) {
      const container = document.getElementById('url-result');
      container.style.display = 'block';

      const isHigh = data.risk_level === 'High Risk';
      const isSuspicious = data.risk_level === 'Suspicious';
      const themeClass = isHigh ? 'high' : (isSuspicious ? 'suspicious' : 'low');
      const strokeColor = isHigh ? '#ef4444' : (isSuspicious ? '#f59e0b' : '#10b981');
      const offset = 200 - (data.risk_score / 100) * 200;

      let reasonsHtml = data.reasons.map(r => `
        <div class="reason-row">
          <div class="reason-dot ${themeClass}"></div>
          <div>${r}</div>
        </div>
      `).join('');

      container.innerHTML = `
        <div class="threat-banner ${themeClass}">
          <div class="gauge-wrapper">
            <svg>
              <circle class="gauge-bg" cx="38" cy="38" r="32"/>
              <circle class="gauge-bar" cx="38" cy="38" r="32" style="stroke:${strokeColor}; stroke-dashoffset:${offset};"/>
            </svg>
            <div class="gauge-val" style="color:${strokeColor}">${data.risk_score}</div>
          </div>
          <div>
            <span class="threat-tag ${themeClass}">${data.risk_level}</span>
            <div class="threat-target">${data.normalized_url}</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:11px; color:var(--text-dim); text-transform:uppercase;">Protocol</div>
            <div style="font-family:var(--font-mono); font-weight:700;">${data.components.scheme.toUpperCase()}</div>
          </div>
        </div>

        <div class="reasons-container">
          <div class="reasons-title">Detected Threat Signals & Heuristics</div>
          ${reasonsHtml}
        </div>

        <div class="metrics-grid">
          <!-- Card 1: Domain & Homograph -->
          <div class="metric-card">
            <div class="metric-head">
              <h4>Homograph & Typosquatting</h4>
              <span class="metric-pill ${data.homograph.typo_detected || data.homograph.is_punycode ? 'danger' : 'success'}">
                ${data.homograph.typo_detected ? 'IMPERSONATION' : (data.homograph.is_punycode ? 'PUNYCODE' : 'CLEAN')}
              </span>
            </div>
            <table class="metric-table">
              <tr><td>Domain:</td><td>${data.components.registered_domain || 'N/A'}</td></tr>
              <tr><td>Subdomain:</td><td>${data.components.subdomain || 'None'}</td></tr>
              <tr><td>Punycode (IDN):</td><td>${data.homograph.is_punycode ? data.homograph.punycode_domain : 'No'}</td></tr>
              <tr><td>Target Brand:</td><td>${data.homograph.target_brand ? data.homograph.target_brand.toUpperCase() : 'None'}</td></tr>
              <tr><td>Similarity:</td><td>${data.homograph.similarity_score ? Math.round(data.homograph.similarity_score * 100) + '%' : 'N/A'}</td></tr>
            </table>
          </div>

          <!-- Card 2: Infrastructure & TLS -->
          <div class="metric-card">
            <div class="metric-head">
              <h4>Infrastructure & TLS / SSL</h4>
              <span class="metric-pill ${data.tls.valid ? 'success' : 'danger'}">
                ${data.tls.valid ? 'TLS VALID' : 'TLS INVALID'}
              </span>
            </div>
            <table class="metric-table">
              <tr><td>Domain Age:</td><td>${data.whois.age_days !== null ? data.whois.age_days + ' days' : (data.whois.error || 'N/A')}</td></tr>
              <tr><td>Registrar:</td><td>${data.whois.registrar || 'Private / Redacted'}</td></tr>
              <tr><td>Cert Issuer:</td><td>${data.tls.issuer || 'Unknown'}</td></tr>
              <tr><td>Days to Expiry:</td><td>${data.tls.days_until_expiration !== null ? data.tls.days_until_expiration + 'd' : 'N/A'}</td></tr>
              <tr><td>SAN Matching:</td><td>${data.tls.san && data.tls.san.length ? data.tls.san.length + ' SAN names' : 'None'}</td></tr>
            </table>
          </div>

          <!-- Card 3: Threat Intelligence -->
          <div class="metric-card">
            <div class="metric-head">
              <h4>Threat Intelligence</h4>
              <span class="metric-pill ${data.virustotal.positives > 0 ? 'danger' : (data.virustotal.checked ? 'success' : 'warning')}">
                ${data.virustotal.positives > 0 ? data.virustotal.positives + ' DETECTIONS' : (data.virustotal.checked ? 'BENIGN' : 'OFFLINE')}
              </span>
            </div>
            <table class="metric-table">
              <tr><td>VT Lookups:</td><td>${data.virustotal.checked ? data.virustotal.positives + '/' + data.virustotal.total : 'Heuristic Mode'}</td></tr>
              <tr><td>Cache Status:</td><td>${data.virustotal.cached ? 'L2 SQLite Hit' : 'Live Query'}</td></tr>
              <tr><td>Heuristic Flags:</td><td>${data.heuristic_flags.length ? data.heuristic_flags.join(', ') : 'None'}</td></tr>
              <tr><td>Timestamp:</td><td>${data.analyzed_at.slice(0, 19).replace('T', ' ')}</td></tr>
            </table>
          </div>
        </div>
      `;
    }

    async function executeEmailScan() {
      const raw_content = document.getElementById('email-target').value.trim();
      if (!raw_content) return;

      const loader = document.getElementById('email-loader');
      const container = document.getElementById('email-result');
      loader.style.display = 'block';
      container.style.display = 'none';

      try {
        const resp = await fetch('/analyze/email', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ raw_content })
        });
        const data = await resp.json();
        renderEmailDashboard(data);
      } catch (err) {
        container.style.display = 'block';
        container.innerHTML = `<div style="color:var(--danger); padding:16px;">Email analysis error: ${err.message}</div>`;
      } finally {
        loader.style.display = 'none';
      }
    }

    function renderEmailDashboard(data) {
      const container = document.getElementById('email-result');
      container.style.display = 'block';

      const isHigh = data.risk_level === 'High Risk';
      const isSuspicious = data.risk_level === 'Suspicious';
      const themeClass = isHigh ? 'high' : (isSuspicious ? 'suspicious' : 'low');
      const strokeColor = isHigh ? '#ef4444' : (isSuspicious ? '#f59e0b' : '#10b981');
      const offset = 200 - (data.risk_score / 100) * 200;

      let reasonsHtml = data.reasons.map(r => `
        <div class="reason-row">
          <div class="reason-dot ${themeClass}"></div>
          <div>${r}</div>
        </div>
      `).join('');

      container.innerHTML = `
        <div class="threat-banner ${themeClass}">
          <div class="gauge-wrapper">
            <svg>
              <circle class="gauge-bg" cx="38" cy="38" r="32"/>
              <circle class="gauge-bar" cx="38" cy="38" r="32" style="stroke:${strokeColor}; stroke-dashoffset:${offset};"/>
            </svg>
            <div class="gauge-val" style="color:${strokeColor}">${data.risk_score}</div>
          </div>
          <div>
            <span class="threat-tag ${themeClass}">${data.risk_level}</span>
            <div class="threat-target" style="font-size:15px;">${data.subject || 'Subject: (None specified)'}</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">From: ${data.mismatch.from_header || 'Unknown'}</div>
          </div>
        </div>

        <div class="reasons-container">
          <div class="reasons-title">Authentication & Identity Anomalies</div>
          ${reasonsHtml}
        </div>

        <div class="metrics-grid">
          <!-- Card 1: DNS Authentication -->
          <div class="metric-card">
            <div class="metric-head">
              <h4>Protocol Authentication</h4>
              <span class="metric-pill ${data.spf.status === 'pass' && data.dmarc.status === 'pass' ? 'success' : 'danger'}">
                ${data.dmarc.status === 'pass' ? 'DMARC PASS' : 'DMARC FAIL'}
              </span>
            </div>
            <table class="metric-table">
              <tr><td>SPF Status:</td><td><strong>${data.spf.status.toUpperCase()}</strong></td></tr>
              <tr><td>SPF Details:</td><td>${data.spf.details}</td></tr>
              <tr><td>DKIM Status:</td><td><strong>${data.dkim.status.toUpperCase()}</strong></td></tr>
              <tr><td>DMARC Status:</td><td><strong>${data.dmarc.status.toUpperCase()}</strong> (${data.dmarc.policy || 'none'})</td></tr>
            </table>
          </div>

          <!-- Card 2: Identity Alignment -->
          <div class="metric-card">
            <div class="metric-head">
              <h4>Sender Identity Alignment</h4>
              <span class="metric-pill ${data.mismatch.reply_to_mismatch || data.mismatch.display_name_spoof ? 'danger' : 'success'}">
                ${data.mismatch.reply_to_mismatch ? 'MISMATCH DETECTED' : 'ALIGNED'}
              </span>
            </div>
            <table class="metric-table">
              <tr><td>From Domain:</td><td>${data.mismatch.from_domain || 'N/A'}</td></tr>
              <tr><td>Reply-To:</td><td>${data.mismatch.reply_to_domain || 'Identical / None'}</td></tr>
              <tr><td>Envelope:</td><td>${data.mismatch.return_path_domain || 'Identical / None'}</td></tr>
              <tr><td>Display Spoof:</td><td>${data.mismatch.display_name_spoof ? '🚨 DETECTED' : 'Clean'}</td></tr>
              <tr><td>Reply Divert:</td><td>${data.mismatch.reply_to_mismatch ? '🚨 YES (DIVERTED)' : 'Aligned'}</td></tr>
            </table>
          </div>
        </div>
      `;
    }

    async function fetchHistory() {
      const tbody = document.getElementById('history-body');
      try {
        const resp = await fetch('/recent');
        const items = await resp.json();
        if (!items || items.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-dim);">No scans logged yet.</td></tr>';
          return;
        }

        tbody.innerHTML = items.map(i => {
          const isHigh = i.risk_level === 'High Risk';
          const isSuspicious = i.risk_level === 'Suspicious';
          const themeClass = isHigh ? 'high' : (isSuspicious ? 'suspicious' : 'low');
          return `
            <tr>
              <td><span style="font-family:var(--font-mono); font-size:11px; text-transform:uppercase; color:var(--text-dim);">${i.type}</span></td>
              <td><span style="font-family:var(--font-mono); font-size:12px;">${i.target}</span></td>
              <td><span style="font-family:var(--font-mono); font-weight:700;">${i.risk_score}/100</span></td>
              <td><span class="threat-tag ${themeClass}">${i.risk_level}</span></td>
              <td style="color:var(--text-dim); font-size:12px;">${i.timestamp}</td>
            </tr>
          `;
        }).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:var(--danger);">Failed to load history</td></tr>';
      }
    }

    function loadSampleEmail(type) {
      if (type === 'spoofed') {
        document.getElementById('email-target').value = `From: "PayPal Account Security" <service@notice-paypal-verification.xyz>
Reply-To: phish-collector@scam-mail.top
Return-Path: <bounce@unrelated-server.net>
Subject: Urgent: Your account has been temporarily restricted!
Date: Fri, 20 Nov 2026 10:14:00 +0000
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of service@notice-paypal-verification.xyz does not designate 198.51.100.1 as permitted sender);
       dkim=fail header.i=@notice-paypal-verification.xyz;
       dmarc=fail (p=REJECT) header.from=notice-paypal-verification.xyz
Message-ID: <spoof-987123@notice-paypal-verification.xyz>

Dear Customer,

Please verify your credentials immediately at http://paypal-account-update.xyz/verify to prevent permanent suspension.`;
      } else {
        document.getElementById('email-target').value = `From: "GitHub Notifications" <notifications@github.com>
Reply-To: noreply@github.com
Return-Path: <noreply@github.com>
Subject: [GitHub] Security alert for your repository
Date: Fri, 20 Nov 2026 09:30:00 +0000
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of notifications@github.com designates 192.30.252.204 as permitted sender);
       dkim=pass header.i=@github.com header.s=pf2014;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2014;
Message-ID: <github/repo/commit/123456@github.com>

A security advisory has been published for your dependency.`;
      }
    }

    function togglePosterDetails() {
      const grid = document.getElementById('poster-vectors-grid');
      const btn = document.getElementById('btn-toggle-poster');
      if (grid.style.display === 'none') {
        grid.style.display = 'grid';
        btn.textContent = 'Hide Anatomy';
      } else {
        grid.style.display = 'none';
        btn.textContent = 'Show Anatomy';
      }
    }

    // Health check initialization
    fetch('/health').then(r => r.json()).then(d => {
      document.getElementById('sys-status').textContent = d.virustotal_configured ? 'Live Engine (VT Active)' : 'Live Engine (Heuristic Mode)';
    }).catch(() => {
      document.getElementById('sys-status').textContent = 'Backend Offline';
    });
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, reload=True)
