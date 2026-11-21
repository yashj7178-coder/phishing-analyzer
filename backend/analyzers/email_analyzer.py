"""
Email Header and Authentication Analyzer.
Implements:
- RFC 822/5322 parsing of raw .eml text and email header blocks
- Header mismatch detection (From vs Reply-To vs Return-Path)
- Display name spoofing detection (impersonation of brands or embedding emails in display name)
- Authentication-Results & Received-SPF token parsing
- DNS TXT record queries via dnspython for SPF, DKIM, and DMARC policies
- Embedded URL extraction and correlated risk assessment
"""

import re
import email
import email.utils
import datetime
from typing import Tuple, List, Optional, Dict, Any

import dns.resolver
import dns.exception

from models import (
    SPFCheckResult,
    DKIMCheckResult,
    DMARCCheckResult,
    HeaderMismatch,
    EmailAnalysisResult,
    URLAnalysisResult,
)
from scoring import score_email
from analyzers.url_analyzer import analyze_url

HIGH_VALUE_BRANDS_EMAIL = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "coinbase", "binance", "steam", "outlook", "yahoo",
    "github", "dropbox", "dhl", "fedex", "usps", "irs", "hrblock"
]

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))"""
)


def extract_domain(address: Optional[str]) -> Optional[str]:
    """Extract lowercase domain name from email address."""
    if not address or "@" not in address:
        return None
    return address.split("@")[-1].strip().lower().rstrip(">").strip()


def query_dns_txt(domain: str, timeout: float = 3.0) -> List[str]:
    """
    Safely query DNS TXT records for a domain with short timeout.
    """
    if not domain or "." not in domain:
        return []

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            txt_string = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
            records.append(txt_string)
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return ["DNS_QUERY_TIMEOUT"]
    except Exception as e:
        return [f"DNS_QUERY_ERROR: {str(e)}"]


def parse_authentication_results(header_val: str) -> Dict[str, str]:
    """
    Parse authres tokens (spf, dkim, dmarc) from Authentication-Results header.
    """
    results: Dict[str, str] = {}
    if not header_val:
        return results

    lower_val = header_val.lower()

    # Search for spf=pass/fail/softfail/neutral/temperror/permerror
    spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|temperror|permerror|none)\b", lower_val)
    if spf_match:
        results["spf"] = spf_match.group(1)

    # Search for dkim=pass/fail/none
    dkim_match = re.search(r"\bdkim=(pass|fail|neutral|temperror|permerror|none)\b", lower_val)
    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    # Search for dmarc=pass/fail/none
    dmarc_match = re.search(r"\bdmarc=(pass|fail|temperror|permerror|none)\b", lower_val)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1)

    return results


def check_spf(sender_domain: Optional[str], auth_results: Dict[str, str], received_spf: Optional[str]) -> SPFCheckResult:
    """
    Verify SPF via Authentication-Results header and DNS TXT fallback.
    """
    header_status = auth_results.get("spf")
    if not header_status and received_spf:
        rec_match = re.search(r"^(pass|fail|softfail|neutral|none)", received_spf.strip().lower())
        if rec_match:
            header_status = rec_match.group(1)

    dns_record = None
    details = ""

    if sender_domain:
        txt_records = query_dns_txt(sender_domain)
        for rec in txt_records:
            if rec.startswith("v=spf1"):
                dns_record = rec
                break

    if header_status:
        status = header_status
        details = f"Reported by server Authentication-Results: {header_status.upper()}"
        if dns_record:
            details += f" | Published DNS SPF: {dns_record}"
        elif sender_domain:
            details += " | No v=spf1 TXT record found in DNS"
    elif dns_record:
        status = "published"
        details = f"Published DNS SPF record found: {dns_record}"
    else:
        status = "none"
        details = "No SPF verification in headers and no v=spf1 TXT record found in DNS"

    return SPFCheckResult(
        status=status,
        header_result=header_status,
        dns_record=dns_record,
        details=details,
    )


def check_dkim(
    sender_domain: Optional[str],
    auth_results: Dict[str, str],
    dkim_signature: Optional[str],
) -> DKIMCheckResult:
    """
    Verify DKIM via header tokens, signature selector, and DNS TXT records.
    """
    header_status = auth_results.get("dkim")
    selector = None
    dns_record = None
    details = ""

    # Parse selector from DKIM-Signature header (s=selector;)
    if dkim_signature:
        s_match = re.search(r"\bs=([a-zA-Z0-9_\-]+)", dkim_signature)
        if s_match:
            selector = s_match.group(1)

    # DNS query on {selector}._domainkey.{sender_domain}
    lookup_selector = selector or "default"
    if sender_domain:
        dkim_lookup_domain = f"{lookup_selector}._domainkey.{sender_domain}"
        txt_records = query_dns_txt(dkim_lookup_domain)
        for rec in txt_records:
            if "v=DKIM1" in rec or "p=" in rec:
                dns_record = rec
                break

    if header_status:
        status = header_status
        details = f"Reported by server Authentication-Results: {header_status.upper()}"
        if selector:
            details += f" (Selector: {selector})"
        if dns_record:
            details += " | DKIM key published in DNS"
    elif dkim_signature:
        status = "signed"
        details = f"DKIM-Signature present on message with selector '{selector or 'unknown'}'"
        if dns_record:
            details += f" | Public key located at {lookup_selector}._domainkey.{sender_domain}"
    else:
        status = "none"
        details = "No DKIM signature present on message"

    return DKIMCheckResult(
        status=status,
        header_result=header_status,
        selector=selector,
        dns_record=dns_record,
        details=details,
    )


def check_dmarc(sender_domain: Optional[str], auth_results: Dict[str, str]) -> DMARCCheckResult:
    """
    Verify DMARC policy from Authentication-Results and DNS TXT _dmarc.<domain>.
    """
    header_status = auth_results.get("dmarc")
    policy = None
    dns_record = None
    details = ""

    if sender_domain:
        dmarc_domain = f"_dmarc.{sender_domain}"
        txt_records = query_dns_txt(dmarc_domain)
        for rec in txt_records:
            if rec.startswith("v=DMARC1"):
                dns_record = rec
                p_match = re.search(r"\bp=([a-zA-Z]+)", rec)
                if p_match:
                    policy = p_match.group(1).lower()
                break

    if header_status:
        status = header_status
        details = f"Reported by server Authentication-Results: {header_status.upper()}"
        if policy:
            details += f" | Enforced Policy: p={policy}"
        if dns_record:
            details += f" | DNS: {dns_record}"
    elif dns_record:
        status = "published"
        details = f"DMARC record published in DNS with policy p={policy or 'none'}"
    else:
        status = "none"
        details = f"No DMARC record published for domain _dmarc.{sender_domain or 'unknown'}"

    return DMARCCheckResult(
        status=status,
        header_result=header_status,
        policy=policy,
        dns_record=dns_record,
        details=details,
    )


def detect_header_mismatches(
    from_raw: Optional[str],
    reply_to_raw: Optional[str],
    return_path_raw: Optional[str],
) -> HeaderMismatch:
    """
    Compare From, Reply-To, and Return-Path headers and flag impersonation / spoofing.
    """
    details: List[str] = []

    # Parse display name and email address for each header
    from_name, from_addr = email.utils.parseaddr(from_raw or "")
    _, reply_to_addr = email.utils.parseaddr(reply_to_raw or "")
    _, return_path_addr = email.utils.parseaddr(return_path_raw or "")

    from_domain = extract_domain(from_addr)
    reply_to_domain = extract_domain(reply_to_addr)
    return_path_domain = extract_domain(return_path_addr)

    reply_to_mismatch = False
    return_path_mismatch = False
    display_name_spoof = False

    # 1. Reply-To Mismatch
    if reply_to_domain and from_domain:
        # Match base domain or subdomains
        if reply_to_domain != from_domain and not (
            from_domain.endswith("." + reply_to_domain) or reply_to_domain.endswith("." + from_domain)
        ):
            reply_to_mismatch = True
            details.append(
                f"From domain ({from_domain}) does not match Reply-To domain ({reply_to_domain})."
            )

    # 2. Return-Path Mismatch
    if return_path_domain and from_domain:
        if return_path_domain != from_domain and not (
            from_domain.endswith("." + return_path_domain) or return_path_domain.endswith("." + from_domain)
        ):
            return_path_mismatch = True
            details.append(
                f"From domain ({from_domain}) differs from envelope Return-Path domain ({return_path_domain})."
            )

    # 3. Display Name Spoofing
    if from_name:
        clean_name = from_name.strip().strip('"\'')
        lower_name = clean_name.lower()

        # Check if display name looks like an email address
        if "@" in clean_name:
            embedded_domain = extract_domain(clean_name)
            if embedded_domain and embedded_domain != from_domain:
                display_name_spoof = True
                details.append(
                    f"Display name '{clean_name}' embeds an email address with domain '{embedded_domain}' differing from actual sender '{from_domain}'."
                )

        # Check if display name claims to be a brand, but from_domain does not match
        for brand in HIGH_VALUE_BRANDS_EMAIL:
            if brand in lower_name and (not from_domain or brand not in from_domain):
                display_name_spoof = True
                details.append(
                    f"Display name '{clean_name}' impersonates brand '{brand.capitalize()}', but sender domain is '{from_domain}'."
                )
                break

    return HeaderMismatch(
        from_header=from_raw,
        from_domain=from_domain,
        from_display_name=from_name if from_name else None,
        reply_to=reply_to_raw,
        reply_to_domain=reply_to_domain,
        return_path=return_path_raw,
        return_path_domain=return_path_domain,
        reply_to_mismatch=reply_to_mismatch,
        return_path_mismatch=return_path_mismatch,
        display_name_spoof=display_name_spoof,
        details=details,
    )


async def analyze_email_content(raw_content: str) -> EmailAnalysisResult:
    """
    Parse email headers or raw .eml, check authentication & DNS records,
    detect mismatches, inspect embedded links, and compute risk score.
    """
    # Parse RFC 822 email message
    msg = email.message_from_string(raw_content)

    subject = msg.get("Subject")
    date_header = msg.get("Date")
    msg_id = msg.get("Message-ID")

    from_header = msg.get("From")
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    auth_results_header = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF")
    dkim_sig = msg.get("DKIM-Signature")

    # Store all captured key headers
    headers_found: Dict[str, str] = {}
    for k in ["From", "To", "Subject", "Date", "Reply-To", "Return-Path", "Authentication-Results", "Received-SPF", "DKIM-Signature"]:
        v = msg.get(k)
        if v:
            headers_found[k] = str(v)

    # 1. Header Mismatches & Impersonation
    mismatch = detect_header_mismatches(from_header, reply_to, return_path)

    # 2. Parse Authentication-Results
    auth_tokens = parse_authentication_results(auth_results_header)

    # 3. Check SPF
    spf_result = check_spf(mismatch.from_domain, auth_tokens, received_spf)

    # 4. Check DKIM
    dkim_result = check_dkim(mismatch.from_domain, auth_tokens, dkim_sig)

    # 5. Check DMARC
    dmarc_result = check_dmarc(mismatch.from_domain, auth_tokens)

    # 6. Extract Embedded URLs from email payload/body
    extracted_urls: List[str] = []
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            payload = part.get_payload(decode=True)
            if payload:
                body_text += " " + payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_text = payload.decode("utf-8", errors="ignore")
        else:
            body_text = raw_content

    # Find URLs
    raw_matches = URL_REGEX.findall(body_text)
    seen = set()
    for match in raw_matches:
        url_candidate = match[0] if isinstance(match, tuple) else match
        if url_candidate.startswith("http") and url_candidate not in seen:
            seen.add(url_candidate)
            extracted_urls.append(url_candidate)

    # Analyze first 3 embedded URLs if present
    url_results: List[URLAnalysisResult] = []
    max_url_score = 0
    for u in extracted_urls[:3]:
        try:
            res = await analyze_url(u)
            url_results.append(res)
            if res.risk_score > max_url_score:
                max_url_score = res.risk_score
        except Exception:
            pass

    # 7. Compute deterministic Risk Score
    risk_score, risk_level, reasons = score_email(
        mismatch=mismatch,
        spf=spf_result,
        dkim=dkim_result,
        dmarc=dmarc_result,
        url_max_score=max_url_score,
    )

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return EmailAnalysisResult(
        subject=subject,
        date=date_header,
        message_id=msg_id,
        headers_found=headers_found,
        extracted_urls=extracted_urls[:15],
        url_results=url_results,
        mismatch=mismatch,
        spf=spf_result,
        dkim=dkim_result,
        dmarc=dmarc_result,
        risk_score=risk_score,
        risk_level=risk_level,
        reasons=reasons,
        analyzed_at=now_iso,
    )
