"""
Comprehensive test suite for Phishing URL & Email Analyzer.
Tests URL parsing, homograph & typosquatting detection, WHOIS age parsing,
header mismatch checks, scoring logic, and FastAPI endpoints.
"""

import sys
import os
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from main import app
from models import (
    RiskLevel,
    WhoisInfo,
    HomographInfo,
    TLSCertInfo,
    VirusTotalInfo,
    HeaderMismatch,
    SPFCheckResult,
    DKIMCheckResult,
    DMARCCheckResult,
)
from scoring import score_url, score_email, map_score_to_level
from analyzers.url_analyzer import (
    parse_url,
    check_homograph_and_typo,
    is_ip_address,
    normalize_leet,
    levenshtein_distance,
    extract_heuristic_flags,
)
from analyzers.email_analyzer import (
    extract_domain,
    detect_header_mismatches,
    parse_authentication_results,
    check_spf,
    check_dkim,
    check_dmarc,
)


@pytest.fixture
def client():
    return TestClient(app)


# --- 1. URL Heuristic & Parsing Tests ---

def test_parse_url_benign():
    url, comps = parse_url("https://github.com/torvalds/linux")
    assert comps.domain == "github"
    assert comps.suffix == "com"
    assert comps.registered_domain == "github.com"
    assert comps.path == "/torvalds/linux"


def test_parse_url_wikipedia():
    url, comps = parse_url("wikipedia.org/wiki/Phishing")
    assert comps.domain == "wikipedia"
    assert comps.suffix == "org"
    assert comps.registered_domain == "wikipedia.org"


def test_is_ip_address():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1") is True
    assert is_ip_address("github.com") is False
    assert is_ip_address("paypa1.com") is False


def test_extract_heuristic_flags_ip_and_keywords():
    _, comps = parse_url("http://192.168.1.100/account/login.php")
    flags = extract_heuristic_flags("http://192.168.1.100/account/login.php", comps)
    assert "IP_AS_HOST" in flags
    assert "PHISHING_KEYWORDS_IN_PATH" in flags
    assert "NO_HTTPS" in flags


def test_extract_heuristic_flags_at_symbol():
    _, comps = parse_url("http://google.com@attacker-controlled.site/login")
    flags = extract_heuristic_flags("http://google.com@attacker-controlled.site/login", comps)
    assert "AT_SYMBOL_IN_URL" in flags


# --- 2. Homograph, Punycode & Typosquatting Tests ---

def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypa1", "paypal") == 1
    assert levenshtein_distance("g00gle", "google") == 2


def test_normalize_leet():
    assert normalize_leet("paypa1") == "paypal"
    assert normalize_leet("g00gle") == "google"
    assert normalize_leet("rnicrosoft") == "microsoft"


def test_homograph_punycode_detection():
    # IDN Punycode domain
    info = check_homograph_and_typo("xn--gogle-pra.com", "xn--gogle-pra")
    assert info.is_punycode is True
    assert info.punycode_domain == "xn--gogle-pra.com"


def test_brand_typosquatting_paypal_lookalike():
    info = check_homograph_and_typo("paypa1.com", "paypa1")
    assert info.typo_detected is True
    assert info.target_brand == "paypal"


def test_brand_typosquatting_rnicrosoft():
    info = check_homograph_and_typo("rnicrosoft.com", "rnicrosoft")
    assert info.typo_detected is True
    assert info.target_brand == "microsoft"


def test_benign_exact_brand_not_flagged_as_typo():
    info_google = check_homograph_and_typo("google.com", "google")
    assert info_google.typo_detected is False

    info_github = check_homograph_and_typo("github.com", "github")
    assert info_github.typo_detected is False


# --- 3. Weighted Scoring Engine Tests ---

def test_score_mapping():
    assert map_score_to_level(15) == RiskLevel.LOW
    assert map_score_to_level(29) == RiskLevel.LOW
    assert map_score_to_level(30) == RiskLevel.SUSPICIOUS
    assert map_score_to_level(69) == RiskLevel.SUSPICIOUS
    assert map_score_to_level(70) == RiskLevel.HIGH_RISK
    assert map_score_to_level(100) == RiskLevel.HIGH_RISK


def test_benign_domain_score():
    whois_info = WhoisInfo(age_days=1500, registrar="MarkMonitor", is_recently_registered=False)
    homograph_info = HomographInfo(is_punycode=False, typo_detected=False)
    tls_info = TLSCertInfo(valid=True, issuer="DigiCert", days_until_expiration=180)
    vt_info = VirusTotalInfo(checked=True, positives=0, total=70)
    heuristic_flags = []

    score, level, reasons = score_url(
        whois_info, homograph_info, tls_info, vt_info, heuristic_flags, has_known_legit_brand_match=True
    )
    assert score < 30
    assert level == RiskLevel.LOW


def test_high_risk_phishing_url_score():
    whois_info = WhoisInfo(age_days=4, is_recently_registered=True)
    homograph_info = HomographInfo(
        is_punycode=True,
        punycode_domain="xn--paypl-era.com",
        typo_detected=True,
        target_brand="paypal",
        explanation="Punycode spoof of PayPal",
    )
    tls_info = TLSCertInfo(valid=False, error="SSL Verification Error: Self-signed certificate")
    vt_info = VirusTotalInfo(checked=True, positives=6, total=72, malicious_engines=["Google Safebrowsing"])
    heuristic_flags = ["PHISHING_KEYWORDS_IN_PATH", "SUSPICIOUS_TLD"]

    score, level, reasons = score_url(whois_info, homograph_info, tls_info, vt_info, heuristic_flags)
    assert score >= 70
    assert level == RiskLevel.HIGH_RISK
    assert any("VirusTotal" in r for r in reasons)
    assert any("registered only 4 days ago" in r or "Punycode" in r for r in reasons)


# --- 4. Email Header & Authentication Tests ---

def test_extract_domain():
    assert extract_domain("user@example.com") == "example.com"
    assert extract_domain("Admin <support@company.org>") == "company.org"
    assert extract_domain("invalid-address") is None


def test_detect_header_mismatches_reply_to():
    mismatch = detect_header_mismatches(
        from_raw="support@bankofamerica.com",
        reply_to_raw="collector@phishing-target.xyz",
        return_path_raw="support@bankofamerica.com",
    )
    assert mismatch.reply_to_mismatch is True
    assert mismatch.return_path_mismatch is False
    assert mismatch.from_domain == "bankofamerica.com"
    assert mismatch.reply_to_domain == "phishing-target.xyz"


def test_detect_display_name_spoofing():
    mismatch = detect_header_mismatches(
        from_raw='"PayPal Account Security" <attacker@randommail.org>',
        reply_to_raw=None,
        return_path_raw=None,
    )
    assert mismatch.display_name_spoof is True
    assert any("PayPal" in d for d in mismatch.details)


def test_parse_authentication_results_tokens():
    header = "mx.google.com; spf=pass (google.com: 1.2.3.4 permitted); dkim=fail; dmarc=fail (p=REJECT)"
    tokens = parse_authentication_results(header)
    assert tokens.get("spf") == "pass"
    assert tokens.get("dkim") == "fail"
    assert tokens.get("dmarc") == "fail"


def test_score_email_legitimate():
    mismatch = HeaderMismatch(from_domain="github.com", reply_to_domain="github.com", return_path_domain="github.com")
    spf = SPFCheckResult(status="pass", details="SPF Pass")
    dkim = DKIMCheckResult(status="pass", details="DKIM Pass")
    dmarc = DMARCCheckResult(status="pass", policy="reject", details="DMARC Pass")

    score, level, reasons = score_email(mismatch, spf, dkim, dmarc)
    assert score < 30
    assert level == RiskLevel.LOW


def test_score_email_spoofed():
    mismatch = HeaderMismatch(
        from_domain="paypal.com",
        reply_to_mismatch=True,
        reply_to_domain="hacker.ru",
        display_name_spoof=True,
        from_display_name="PayPal Alert",
    )
    spf = SPFCheckResult(status="fail", details="SPF Fail")
    dkim = DKIMCheckResult(status="fail", details="DKIM Fail")
    dmarc = DMARCCheckResult(status="fail", policy="reject", details="DMARC Fail p=reject")

    score, level, reasons = score_email(mismatch, spf, dkim, dmarc)
    assert score >= 70
    assert level == RiskLevel.HIGH_RISK
    assert any("DMARC" in r for r in reasons)
    assert any("Sender domain mismatch" in r or "Reply-To" in r for r in reasons)


# --- 5. FastAPI Integration Tests ---

def test_api_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "virustotal_configured" in data


def test_api_analyze_url_benign(client, monkeypatch):
    from analyzers import url_analyzer
    monkeypatch.setattr(
        url_analyzer,
        "check_domain_age",
        lambda domain: WhoisInfo(age_days=5000, registrar="MarkMonitor", is_recently_registered=False),
    )
    monkeypatch.setattr(
        url_analyzer,
        "check_tls_certificate",
        lambda hostname: TLSCertInfo(valid=True, issuer="DigiCert", days_until_expiration=120),
    )

    response = client.post("/analyze/url", json={"url": "https://wikipedia.org"})
    assert response.status_code == 200
    data = response.json()
    assert data["components"]["domain"] == "wikipedia"
    assert "risk_score" in data
    assert "risk_level" in data
    assert isinstance(data["reasons"], list)


def test_api_analyze_url_typo(client, monkeypatch):
    from analyzers import url_analyzer
    monkeypatch.setattr(
        url_analyzer,
        "check_domain_age",
        lambda domain: WhoisInfo(age_days=5, registrar="Namecheap", is_recently_registered=True),
    )
    monkeypatch.setattr(
        url_analyzer,
        "check_tls_certificate",
        lambda hostname: TLSCertInfo(valid=False, error="Self-signed certificate"),
    )

    response = client.post("/analyze/url", json={"url": "http://paypa1-security.xyz/login"})
    assert response.status_code == 200
    data = response.json()
    assert data["homograph"]["typo_detected"] is True
    assert data["homograph"]["target_brand"] == "paypal"
    assert data["risk_score"] >= 30  # Should be suspicious or high risk


def test_api_analyze_url_batch(client, monkeypatch):
    from analyzers import url_analyzer
    monkeypatch.setattr(
        url_analyzer,
        "check_domain_age",
        lambda domain: WhoisInfo(age_days=2000, is_recently_registered=False),
    )
    monkeypatch.setattr(
        url_analyzer,
        "check_tls_certificate",
        lambda hostname: TLSCertInfo(valid=True, issuer="DigiCert"),
    )

    urls = ["https://github.com", "http://paypa1-login.com"]
    response = client.post("/analyze/url/batch", json={"urls": urls})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["results"]) == 2


def test_api_analyze_email_spoofed(client, monkeypatch):
    from analyzers import email_analyzer
    monkeypatch.setattr(email_analyzer, "query_dns_txt", lambda domain, timeout=3.0: [])

    raw_email = """From: "PayPal Security" <security@update-notice.xyz>
Reply-To: phisher@scammail.top
Return-Path: <bounce@unrelated.net>
Subject: Urgent Security Warning
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail (p=REJECT)

Please verify your credentials immediately."""
    response = client.post("/analyze/email", json={"raw_content": raw_email})
    assert response.status_code == 200
    data = response.json()
    assert data["mismatch"]["reply_to_mismatch"] is True
    assert data["mismatch"]["display_name_spoof"] is True
    assert data["risk_level"] == "High Risk"
    assert data["risk_score"] >= 70


def test_api_recent_scans(client):
    response = client.get("/recent")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_api_web_dashboard_html(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Phishing URL & Email Analyzer" in response.text
