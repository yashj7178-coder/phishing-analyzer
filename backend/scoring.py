"""
Risk Scoring Engine for URLs and Emails.
Computes deterministic 0-100 risk score and categorizes into Low, Suspicious, or High Risk,
with clear, human-readable explanations.
"""

from typing import List, Tuple, Optional
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


def map_score_to_level(score: int) -> RiskLevel:
    """Map numeric score (0-100) to RiskLevel enum."""
    if score >= 70:
        return RiskLevel.HIGH_RISK
    elif score >= 30:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.LOW


def score_url(
    whois_info: WhoisInfo,
    homograph_info: HomographInfo,
    tls_info: TLSCertInfo,
    vt_info: VirusTotalInfo,
    heuristic_flags: List[str],
    has_known_legit_brand_match: bool = False,
) -> Tuple[int, RiskLevel, List[str]]:
    """
    Calculate deterministic risk score for a URL.
    Returns: (score, RiskLevel, list_of_reasons)
    """
    score = 0
    reasons: List[str] = []

    # 1. Threat Intelligence (VirusTotal)
    if vt_info.checked:
        if vt_info.positives >= 5:
            score += 85
            reasons.append(
                f"VirusTotal threat intelligence: flagged as malicious by {vt_info.positives}/{vt_info.total} security vendors."
            )
        elif vt_info.positives >= 2:
            score += 55
            reasons.append(
                f"VirusTotal threat intelligence: flagged as suspicious by {vt_info.positives}/{vt_info.total} security vendors."
            )
        elif vt_info.positives == 1:
            score += 30
            reasons.append(
                f"VirusTotal alert: 1 security vendor flagged this indicator as suspicious."
            )
        else:
            # Clean VT reputation can slightly offset trivial heuristics
            score -= 5

    # 2. Homograph, Punycode & Brand Typo
    if homograph_info.is_punycode:
        score += 45
        reasons.append(
            f"Internationalized Domain Name (IDN / Punycode: {homograph_info.punycode_domain}) detected. Often used for deceptive character spoofing."
        )

    if homograph_info.has_non_ascii:
        score += 30
        reasons.append(
            "Domain contains non-ASCII or mixed-script unicode glyphs resembling latin characters."
        )

    if homograph_info.typo_detected and homograph_info.target_brand:
        score += 45
        brand_name = homograph_info.target_brand.capitalize()
        reasons.append(
            f"Brand impersonation / typosquatting detected targeting '{brand_name}' ({homograph_info.explanation or 'similarity match'})."
        )

    # 3. WHOIS Domain Age
    if whois_info.age_days is not None:
        if whois_info.age_days < 7:
            score += 40
            reasons.append(
                f"Newly registered domain: created only {whois_info.age_days} days ago (< 7 days). High phishing correlation."
            )
        elif whois_info.age_days < 30:
            score += 25
            reasons.append(
                f"Recently registered domain: created {whois_info.age_days} days ago (< 30 days)."
            )
        elif whois_info.age_days < 90:
            score += 10
            reasons.append(
                f"Domain is relatively new ({whois_info.age_days} days old)."
            )
        elif whois_info.age_days > 730:
            # Established domain (> 2 years old)
            score -= 5

    if whois_info.is_recently_registered and whois_info.age_days is None:
        score += 25
        reasons.append("Domain WHOIS creation records indicate recent registration.")

    # 4. TLS/SSL Certificate Inspection
    if not tls_info.valid:
        if tls_info.error:
            if "expired" in tls_info.error.lower():
                score += 30
                reasons.append(f"TLS/SSL Certificate is expired: {tls_info.error}")
            elif "mismatch" in tls_info.error.lower() or "hostname" in tls_info.error.lower():
                score += 35
                reasons.append(f"TLS/SSL Certificate hostname mismatch: {tls_info.error}")
            elif "self-signed" in tls_info.error.lower() or "verify" in tls_info.error.lower():
                score += 35
                reasons.append(f"TLS/SSL Certificate cannot be verified (possible self-signed or invalid CA): {tls_info.error}")
            else:
                score += 20
                reasons.append(f"TLS/SSL Connection issue: {tls_info.error}")
    else:
        # Valid certificate
        if tls_info.days_until_expiration is not None and tls_info.days_until_expiration < 5:
            score += 10
            reasons.append(
                f"TLS/SSL certificate expires in {tls_info.days_until_expiration} days."
            )

    # 5. Heuristic Indicators
    heuristic_weights = {
        "IP_AS_HOST": (40, "URL host is an IP address instead of a domain name (frequently used in phishing)."),
        "AT_SYMBOL_IN_URL": (35, "URL contains '@' symbol, which can mislead users about the true destination host."),
        "SUSPICIOUS_TLD": (20, "Domain uses a high-abuse top-level domain frequently associated with spam and phishing campaigns."),
        "EXCESSIVE_SUBDOMAINS": (20, "Domain contains an excessive number of subdomains (>= 4 levels)."),
        "PHISHING_KEYWORDS_IN_PATH": (20, "URL path or subdomain contains sensitive security/credential keywords (e.g. login, verify, account)."),
        "VERY_LONG_URL": (10, "Excessively long URL string (> 120 characters), often used to hide the true destination."),
        "HEX_OR_ENCODED_DECEPTION": (25, "URL contains unusual hex or percent encoding tricks to disguise destination."),
        "NO_HTTPS": (15, "Target does not enforce HTTPS encryption on web port 443."),
    }

    for flag in heuristic_flags:
        if flag in heuristic_weights:
            weight, description = heuristic_weights[flag]
            score += weight
            reasons.append(description)

    # Benign domain mitigation: If domain is a direct exact match to a verified authentic brand and no spoofing
    if has_known_legit_brand_match and not homograph_info.typo_detected and not homograph_info.is_punycode:
        # established major platform with valid SSL
        if tls_info.valid and (whois_info.age_days is None or whois_info.age_days > 365):
            score = min(score, 15)

    # Clamp score to [0, 100]
    final_score = max(0, min(100, score))
    risk_level = map_score_to_level(final_score)

    if not reasons and final_score < 30:
        reasons.append("No active threat indicators or deceptive attributes detected. Standard benign profile.")

    return final_score, risk_level, reasons


def score_email(
    mismatch: HeaderMismatch,
    spf: SPFCheckResult,
    dkim: DKIMCheckResult,
    dmarc: DMARCCheckResult,
    url_max_score: int = 0,
) -> Tuple[int, RiskLevel, List[str]]:
    """
    Calculate deterministic risk score for parsed email headers and authentication.
    Returns: (score, RiskLevel, list_of_reasons)
    """
    score = 0
    reasons: List[str] = []

    # 1. Header Mismatches (From vs Reply-To vs Return-Path)
    if mismatch.reply_to_mismatch:
        score += 35
        reasons.append(
            f"Sender domain mismatch: 'From' header ({mismatch.from_domain}) differs from 'Reply-To' ({mismatch.reply_to_domain}). Responses will be routed to an alternate domain."
        )

    if mismatch.return_path_mismatch:
        score += 20
        reasons.append(
            f"Envelope mismatch: 'From' header ({mismatch.from_domain}) differs from envelope 'Return-Path' ({mismatch.return_path_domain})."
        )

    if mismatch.display_name_spoof:
        score += 35
        reasons.append(
            f"Display name spoofing detected: Display name '{mismatch.from_display_name}' attempts to impersonate a brand or contains an email address distinct from the actual sending domain."
        )

    # 2. DMARC Evaluation
    dmarc_status = (dmarc.status or "").lower()
    if dmarc_status in ("fail", "failed", "reject"):
        if dmarc.policy == "reject":
            score += 40
            reasons.append("DMARC check failed with strict 'p=reject' policy. Email domain was likely spoofed.")
        elif dmarc.policy == "quarantine":
            score += 35
            reasons.append("DMARC check failed with 'p=quarantine' policy. High probability of sender spoofing.")
        else:
            score += 30
            reasons.append("DMARC verification failed for sending domain.")
    elif dmarc_status == "none" or "no dmarc" in dmarc.details.lower():
        score += 15
        reasons.append("Domain lacks a published DMARC DNS record, making it vulnerable to direct domain spoofing.")
    elif dmarc_status == "pass":
        score -= 10

    # 3. SPF Evaluation
    spf_status = (spf.status or "").lower()
    if spf_status in ("fail", "hardfail"):
        score += 30
        reasons.append("SPF (Sender Policy Framework) check failed. Sending server is not authorized to send for this domain.")
    elif spf_status in ("softfail", "~all"):
        score += 20
        reasons.append("SPF softfail: Sender IP is not explicitly authorized under domain's SPF policy.")
    elif spf_status in ("neutral", "none"):
        score += 10
        reasons.append("SPF policy is neutral or missing for sending domain.")
    elif spf_status == "pass":
        score -= 10

    # 4. DKIM Evaluation
    dkim_status = (dkim.status or "").lower()
    if dkim_status in ("fail", "failed", "bad_signature"):
        score += 25
        reasons.append("DKIM cryptographic signature verification failed. Message may have been altered in transit.")
    elif dkim_status in ("none", "missing"):
        score += 10
        reasons.append("No valid DKIM signature found on the message.")
    elif dkim_status == "pass":
        score -= 10

    # 5. Embedded URL risk contribution
    if url_max_score >= 70:
        score += 45
        reasons.append("Email body contains links identified as High Risk / Phishing URLs.")
    elif url_max_score >= 30:
        score += 25
        reasons.append("Email body contains links flagged as Suspicious.")

    final_score = max(0, min(100, score))
    risk_level = map_score_to_level(final_score)

    if not reasons and final_score < 30:
        reasons.append("Email authentication headers (SPF, DKIM, DMARC) and sender identities align properly. Legitimate profile.")

    return final_score, risk_level, reasons
