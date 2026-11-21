"""
URL Heuristic and Reputation Analyzer.
Implements:
- URL parsing with tldextract & urllib.parse
- WHOIS domain age inspection with resilient timeout and list/string date handling
- Homograph, Punycode (IDN), and brand typosquatting / Levenshtein detection
- TLS/SSL certificate verification, expiration, SAN, and issuer extraction
- VirusTotal v3 Threat Intelligence with SQLite and In-Memory TTL caching
"""

import os
import re
import ssl
import time
import socket
import base64
import sqlite3
import datetime
import ipaddress
import urllib.parse
import concurrent.futures
from typing import Tuple, List, Optional, Dict, Any

import idna
import httpx
import tldextract
import whois
from dotenv import load_dotenv

from models import (
    URLComponents,
    WhoisInfo,
    HomographInfo,
    TLSCertInfo,
    VirusTotalInfo,
    URLAnalysisResult,
)
from scoring import score_url

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "cache.db")

# High-value brand list targeted frequently by phishing attacks
HIGH_VALUE_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "github", "dropbox",
    "chase", "wellsfargo", "bankofamerica", "citibank", "coinbase", "binance",
    "steam", "outlook", "yahoo", "ebay", "adobe", "spotify", "walmart",
    "target", "fedex", "dhl", "usps", "telegram", "whatsapp", "zoom",
    "meta", "icloud", "onedrive", "roblox", "reddit", "stripe", "kraken"
]

# Suspicious TLDs with historically high abuse rates
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "buzz", "fit", "country", "kim", "work",
    "gq", "cf", "ml", "tk", "ga", "rest", "icu", "cam", "live", "link"
}

# Common leet / optical character substitutions
LEET_SUBS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "vv": "w",
    "rn": "m",
    "cl": "d",
}

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "secure", "security", "update", "banking", "wallet",
    "support", "confirm", "confirmation", "auth", "authenticate",
    "credential", "recover", "recovery", "password", "billing", "invoice",
    "service", "portal", "helpdesk", "validate", "suspended", "unusual"
]

# In-memory L1 cache: key -> (dict_result, expire_timestamp)
_MEM_CACHE: Dict[str, Tuple[Dict[str, Any], float]] = {}


def init_sqlite_cache():
    """Initialize SQLite TTL cache table for threat intelligence lookups."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vt_cache (
                indicator TEXT PRIMARY KEY,
                positives INTEGER,
                total INTEGER,
                malicious_engines TEXT,
                permalink TEXT,
                cached_at INTEGER,
                expires_at INTEGER
            )
            """
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Cache Init Error] {e}")


init_sqlite_cache()


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_leet(text: str) -> str:
    """Normalize optical leet and multi-char substitutions (e.g. rn -> m, 0 -> o)."""
    normalized = text.lower()
    # Replace multi-character substitutions first
    for pattern in ["vv", "rn", "cl"]:
        normalized = normalized.replace(pattern, LEET_SUBS[pattern])
    for char, replacement in LEET_SUBS.items():
        if len(char) == 1:
            normalized = normalized.replace(char, replacement)
    return normalized


def parse_url(raw_url: str) -> Tuple[str, URLComponents]:
    """
    Ensure scheme exists and decompose URL into structured components.
    """
    cleaned = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned

    parsed = urllib.parse.urlparse(cleaned)
    hostname = parsed.hostname or ""

    # tldextract extracts subdomain, domain, suffix
    extracted = tldextract.extract(hostname)
    registered_domain = getattr(extracted, "top_domain_under_public_suffix", "") or extracted.registered_domain
    if not registered_domain:
        registered_domain = hostname

    components = URLComponents(
        scheme=parsed.scheme or "http",
        domain=extracted.domain or hostname,
        subdomain=extracted.subdomain or "",
        suffix=extracted.suffix or "",
        registered_domain=registered_domain,
        path=parsed.path or "/",
        query=parsed.query or "",
    )
    return cleaned, components


def is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def check_homograph_and_typo(hostname: str, domain_name: str) -> HomographInfo:
    """
    Detect Punycode, non-ASCII deceptive glyphs, and brand typosquatting.
    """
    is_punycode = False
    punycode_domain = None
    has_non_ascii = False

    # Check for Punycode
    if "xn--" in hostname.lower():
        is_punycode = True
        punycode_domain = hostname
        try:
            decoded = idna.decode(hostname)
            # Compare decoded vs hostname
            if decoded != hostname:
                has_non_ascii = any(ord(c) > 127 for c in decoded)
        except Exception:
            has_non_ascii = True
    else:
        has_non_ascii = any(ord(c) > 127 for c in hostname)

    # Check typosquatting against known high-value brands
    target_brand = None
    typo_detected = False
    similarity_score = None
    explanation = None

    candidate_domain = domain_name.lower()
    normalized_candidate = normalize_leet(candidate_domain)

    # If domain directly equals a brand (e.g. google.com -> domain 'google'), it's the exact brand
    # We look for lookalike variants: distance 1 or 2, or leet match, but NOT identical
    for brand in HIGH_VALUE_BRANDS:
        if candidate_domain == brand:
            # Exact match, authentic domain candidate
            continue

        # Check leet normalization match (e.g. 'g00gle' normalized is 'google')
        if normalized_candidate == brand:
            typo_detected = True
            target_brand = brand
            similarity_score = 0.95
            explanation = f"Exact leetspeak substitution of brand '{brand}' (e.g. 0->o, 1->l, rn->m)"
            break

        # Check Levenshtein distance
        dist = levenshtein_distance(candidate_domain, brand)
        max_len = max(len(candidate_domain), len(brand))
        ratio = 1.0 - (dist / max_len)

        # Distance of 1 (e.g. 'gogle', 'microsft', 'paypa1') or 2 for longer brands
        if (dist == 1 and max_len >= 4) or (dist == 2 and max_len >= 7):
            typo_detected = True
            target_brand = brand
            similarity_score = round(ratio, 2)
            explanation = f"Levenshtein distance {dist} from '{brand}' ({round(ratio * 100)}% similarity)"
            break

        # Also check if brand is embedded in domain with hyphens or prefixes (e.g. 'paypal-update', 'login-apple', 'paypa1-security')
        if ((brand in candidate_domain) or (brand in normalized_candidate)) and len(candidate_domain) > len(brand) + 2:
            typo_detected = True
            target_brand = brand
            similarity_score = 0.85
            explanation = f"Brand '{brand}' (or lookalike variant) embedded into compound domain name"
            break

    return HomographInfo(
        is_punycode=is_punycode,
        punycode_domain=punycode_domain,
        has_non_ascii=has_non_ascii,
        target_brand=target_brand,
        typo_detected=typo_detected,
        similarity_score=similarity_score,
        explanation=explanation,
    )


def _raw_whois_call(domain: str):
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.5)
        return whois.whois(domain)
    finally:
        socket.setdefaulttimeout(old_timeout)


def check_domain_age(domain: str, timeout: float = 3.0) -> WhoisInfo:
    """
    Safely query WHOIS with strict thread timeout and error handling.
    Gracefully parses creation date (supports datetime, list of datetimes, strings).
    """
    if is_ip_address(domain) or not domain or "." not in domain:
        return WhoisInfo(error="IP address or local hostname, WHOIS skipped")

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_raw_whois_call, domain)
        w = future.result(timeout=timeout)
        executor.shutdown(wait=False, cancel_futures=True)
    except concurrent.futures.TimeoutError:
        executor.shutdown(wait=False, cancel_futures=True)
        return WhoisInfo(error="WHOIS lookup timed out (3s threshold)")
    except Exception as e:
        executor.shutdown(wait=False, cancel_futures=True)
        return WhoisInfo(error=f"WHOIS lookup failed: {type(e).__name__}")

    try:
        creation_date = getattr(w, "creation_date", None)
        registrar = getattr(w, "registrar", None)

        if isinstance(registrar, list) and registrar:
            registrar = str(registrar[0])

        parsed_date: Optional[datetime.datetime] = None

        if isinstance(creation_date, list) and creation_date:
            first = creation_date[0]
            if isinstance(first, datetime.datetime):
                parsed_date = first
            elif isinstance(first, str):
                try:
                    parsed_date = datetime.datetime.fromisoformat(first.replace("Z", "+00:00"))
                except Exception:
                    pass
        elif isinstance(creation_date, datetime.datetime):
            parsed_date = creation_date
        elif isinstance(creation_date, str):
            try:
                parsed_date = datetime.datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
            except Exception:
                pass

        if parsed_date:
            # Normalize timezone
            if parsed_date.tzinfo is not None:
                parsed_date = parsed_date.replace(tzinfo=None)
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            age_days = (now - parsed_date).days
            is_recent = age_days < 30
            return WhoisInfo(
                creation_date=parsed_date.strftime("%Y-%m-%d %H:%M:%S"),
                age_days=age_days,
                registrar=str(registrar) if registrar else None,
                is_recently_registered=is_recent,
            )
        else:
            return WhoisInfo(
                registrar=str(registrar) if registrar else None,
                error="Creation date unavailable in WHOIS record"
            )

    except Exception as e:
        # Handles connection refused, socket timeout, whois server errors
        return WhoisInfo(error=f"WHOIS lookup failed or timed out: {type(e).__name__}")


def _raw_tls_check(hostname: str, timeout: float = 2.5) -> TLSCertInfo:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return TLSCertInfo(valid=False, error="Empty certificate returned")

                # Extract Issuer
                issuer_parts = []
                for field in cert.get("issuer", ()):
                    for k, v in field:
                        if k in ("organizationName", "commonName"):
                            issuer_parts.append(f"{k}={v}")
                issuer_str = ", ".join(issuer_parts) if issuer_parts else "Unknown Issuer"

                # Extract SAN (Subject Alternative Name)
                san_list = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

                # Expiration check
                not_after_str = cert.get("notAfter")
                days_until_exp = None
                is_expired = False

                if not_after_str:
                    try:
                        exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                        delta = exp_date - now
                        days_until_exp = delta.days
                        is_expired = days_until_exp < 0
                    except Exception:
                        pass

                return TLSCertInfo(
                    valid=not is_expired,
                    issuer=issuer_str,
                    san=san_list[:10],
                    days_until_expiration=days_until_exp,
                    is_expired=is_expired,
                )

    except ssl.SSLCertVerificationError as e:
        return TLSCertInfo(valid=False, error=f"SSL Verification Error: {e.verify_message}")
    except (socket.timeout, TimeoutError):
        return TLSCertInfo(valid=False, error="Connection to port 443 timed out (3s threshold)")
    except ConnectionRefusedError:
        return TLSCertInfo(valid=False, error="Port 443 connection refused (No HTTPS service)")
    except Exception as e:
        return TLSCertInfo(valid=False, error=f"TLS check failed: {type(e).__name__} ({str(e)})")


def check_tls_certificate(hostname: str, timeout: float = 3.0) -> TLSCertInfo:
    """
    Inspect SSL/TLS certificate on port 443 with a 3s short timeout.
    Extracts validity, issuer, Subject Alternative Names (SAN), and expiration.
    """
    if is_ip_address(hostname):
        return TLSCertInfo(valid=False, error="Target host is an IP address; standard TLS cert verification not applicable")

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_raw_tls_check, hostname, timeout=timeout)
        res = future.result(timeout=timeout)
        executor.shutdown(wait=False, cancel_futures=True)
        return res
    except concurrent.futures.TimeoutError:
        executor.shutdown(wait=False, cancel_futures=True)
        return TLSCertInfo(valid=False, error="TLS connection timed out (3s threshold)")
    except Exception as e:
        executor.shutdown(wait=False, cancel_futures=True)
        return TLSCertInfo(valid=False, error=f"TLS check failed: {type(e).__name__}")


async def query_virustotal(target_url: str, registered_domain: str) -> VirusTotalInfo:
    """
    Query VirusTotal API v3 with SQLite + Memory TTL caching.
    """
    indicator = registered_domain.lower() if registered_domain else target_url.lower()
    now_ts = time.time()

    # 1. Check in-memory cache
    if indicator in _MEM_CACHE:
        cached_data, expires_at = _MEM_CACHE[indicator]
        if now_ts < expires_at:
            return VirusTotalInfo(
                checked=True,
                positives=cached_data.get("positives", 0),
                total=cached_data.get("total", 0),
                malicious_engines=cached_data.get("malicious_engines", []),
                cached=True,
                permalink=cached_data.get("permalink"),
            )

    # 2. Check SQLite cache
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT positives, total, malicious_engines, permalink, expires_at FROM vt_cache WHERE indicator = ?",
            (indicator,),
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            positives, total, engines_str, permalink, expires_at = row
            if now_ts < expires_at:
                engines_list = engines_str.split(",") if engines_str else []
                # Populate memory cache
                _MEM_CACHE[indicator] = ({
                    "positives": positives,
                    "total": total,
                    "malicious_engines": engines_list,
                    "permalink": permalink,
                }, expires_at)
                return VirusTotalInfo(
                    checked=True,
                    positives=positives,
                    total=total,
                    malicious_engines=engines_list,
                    cached=True,
                    permalink=permalink,
                )
    except Exception as e:
        print(f"[SQLite Cache Read Error] {e}")

    # 3. If API Key is missing, skip external lookup gracefully
    if not VIRUSTOTAL_API_KEY:
        return VirusTotalInfo(
            checked=False,
            error="VirusTotal API key not configured (heuristic and offline analysis active)"
        )

    # 4. Perform HTTP API Query via httpx
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}

            # Query domain reputation
            domain_to_check = registered_domain or target_url
            api_url = f"https://www.virustotal.com/api/v3/domains/{domain_to_check}"
            response = await client.get(api_url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                results = attributes.get("last_analysis_results", {})

                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                malicious_engines = [
                    k for k, v in results.items() if v.get("category") in ("malicious", "suspicious")
                ][:8]

                permalink = f"https://www.virustotal.com/gui/domain/{domain_to_check}"
                expires_at = now_ts + CACHE_TTL_SECONDS

                # Save to caches
                _MEM_CACHE[indicator] = ({
                    "positives": positives,
                    "total": total,
                    "malicious_engines": malicious_engines,
                    "permalink": permalink,
                }, expires_at)

                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO vt_cache
                        (indicator, positives, total, malicious_engines, permalink, cached_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (indicator, positives, total, ",".join(malicious_engines), permalink, int(now_ts), int(expires_at)),
                    )
                    conn.commit()
                    conn.close()
                except Exception as db_err:
                    print(f"[SQLite Write Error] {db_err}")

                return VirusTotalInfo(
                    checked=True,
                    positives=positives,
                    total=total,
                    malicious_engines=malicious_engines,
                    cached=False,
                    permalink=permalink,
                )
            elif response.status_code == 404:
                return VirusTotalInfo(checked=True, positives=0, total=0, cached=False)
            else:
                return VirusTotalInfo(
                    checked=False,
                    error=f"VirusTotal API responded with HTTP {response.status_code}"
                )

    except Exception as e:
        return VirusTotalInfo(checked=False, error=f"VirusTotal query error: {str(e)}")


def extract_heuristic_flags(raw_url: str, components: URLComponents) -> List[str]:
    """
    Evaluate behavioral heuristics and deceptive URL patterns.
    """
    flags: List[str] = []
    hostname = components.domain
    if components.registered_domain:
        hostname = components.registered_domain

    # 1. IP address host
    if is_ip_address(components.domain) or is_ip_address(components.registered_domain):
        flags.append("IP_AS_HOST")

    # 2. '@' symbol in URL
    if "@" in raw_url:
        flags.append("AT_SYMBOL_IN_URL")

    # 3. Suspicious TLD
    if components.suffix.lower() in SUSPICIOUS_TLDS:
        flags.append("SUSPICIOUS_TLDS" if "SUSPICIOUS_TLDS" in flags else "SUSPICIOUS_TLD")

    # 4. Excessive subdomains (>= 3 dots in hostname before suffix)
    subdomain_parts = [p for p in components.subdomain.split(".") if p]
    if len(subdomain_parts) >= 3:
        flags.append("EXCESSIVE_SUBDOMAINS")

    # 5. Phishing keywords in path or subdomain
    lower_path_and_sub = (components.subdomain + "/" + components.path).lower()
    for kw in PHISHING_KEYWORDS:
        if kw in lower_path_and_sub:
            flags.append("PHISHING_KEYWORDS_IN_PATH")
            break

    # 6. Very long URL (> 120 chars)
    if len(raw_url) > 120:
        flags.append("VERY_LONG_URL")

    # 7. Obfuscated / hex tricks
    if "%2f" in raw_url.lower() or "%3a" in raw_url.lower() or "//" in components.path:
        flags.append("HEX_OR_ENCODED_DECEPTION")

    # 8. Plain HTTP
    if components.scheme == "http":
        flags.append("NO_HTTPS")

    return flags


async def analyze_url(url: str) -> URLAnalysisResult:
    """
    Full pipeline to analyze a URL:
    - Normalization & parsing
    - Homograph & typo check
    - WHOIS registration age
    - TLS certificate inspection
    - Threat intelligence lookup (VirusTotal)
    - Heuristics & deterministic scoring
    """
    normalized_url, components = parse_url(url)
    hostname = components.registered_domain or components.domain

    # 1. Homograph & Typosquatting
    homograph_info = check_homograph_and_typo(hostname, components.domain)

    # 2. WHOIS
    whois_info = check_domain_age(components.registered_domain)

    # 3. TLS Certificate Inspection
    tls_info = check_tls_certificate(hostname)

    # 4. VirusTotal Threat Intelligence
    vt_info = await query_virustotal(normalized_url, components.registered_domain)

    # 5. Heuristic Indicators
    heuristic_flags = extract_heuristic_flags(normalized_url, components)

    # Authentic brand match check for benign mitigation
    is_legit_brand = components.domain.lower() in HIGH_VALUE_BRANDS and not homograph_info.typo_detected

    # 6. Scoring Engine
    risk_score, risk_level, reasons = score_url(
        whois_info=whois_info,
        homograph_info=homograph_info,
        tls_info=tls_info,
        vt_info=vt_info,
        heuristic_flags=heuristic_flags,
        has_known_legit_brand_match=is_legit_brand,
    )

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return URLAnalysisResult(
        url=url,
        normalized_url=normalized_url,
        components=components,
        risk_score=risk_score,
        risk_level=risk_level,
        reasons=reasons,
        whois=whois_info,
        homograph=homograph_info,
        tls=tls_info,
        virustotal=vt_info,
        heuristic_flags=heuristic_flags,
        analyzed_at=now_iso,
    )
