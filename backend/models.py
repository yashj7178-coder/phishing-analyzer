from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "Low"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"


# --- URL Analysis Models ---

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL or domain to analyze")


class BatchURLAnalysisRequest(BaseModel):
    urls: List[str] = Field(..., description="List of URLs to analyze")


class URLComponents(BaseModel):
    scheme: str
    domain: str
    subdomain: str
    suffix: str
    registered_domain: str
    path: str
    query: str


class WhoisInfo(BaseModel):
    creation_date: Optional[str] = None
    age_days: Optional[int] = None
    registrar: Optional[str] = None
    is_recently_registered: bool = False
    error: Optional[str] = None


class HomographInfo(BaseModel):
    is_punycode: bool = False
    punycode_domain: Optional[str] = None
    has_non_ascii: bool = False
    target_brand: Optional[str] = None
    typo_detected: bool = False
    similarity_score: Optional[float] = None
    explanation: Optional[str] = None


class TLSCertInfo(BaseModel):
    valid: bool = False
    issuer: Optional[str] = None
    san: List[str] = []
    days_until_expiration: Optional[int] = None
    is_expired: bool = False
    error: Optional[str] = None


class VirusTotalInfo(BaseModel):
    checked: bool = False
    positives: int = 0
    total: int = 0
    malicious_engines: List[str] = []
    cached: bool = False
    permalink: Optional[str] = None
    error: Optional[str] = None


class URLAnalysisResult(BaseModel):
    url: str
    normalized_url: str
    components: URLComponents
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    reasons: List[str] = []
    whois: WhoisInfo
    homograph: HomographInfo
    tls: TLSCertInfo
    virustotal: VirusTotalInfo
    heuristic_flags: List[str] = []
    analyzed_at: str


class BatchURLAnalysisResult(BaseModel):
    results: List[URLAnalysisResult]
    total: int


# --- Email Analysis Models ---

class EmailAnalysisRequest(BaseModel):
    raw_content: str = Field(..., description="Raw RFC 822 .eml content or pasted header block")


class SPFCheckResult(BaseModel):
    status: str = "unknown"  # pass, fail, softfail, neutral, none, permerror, temperror, unknown
    header_result: Optional[str] = None
    dns_record: Optional[str] = None
    details: str = ""


class DKIMCheckResult(BaseModel):
    status: str = "unknown"
    header_result: Optional[str] = None
    selector: Optional[str] = None
    dns_record: Optional[str] = None
    details: str = ""


class DMARCCheckResult(BaseModel):
    status: str = "unknown"
    header_result: Optional[str] = None
    policy: Optional[str] = None
    dns_record: Optional[str] = None
    details: str = ""


class HeaderMismatch(BaseModel):
    from_header: Optional[str] = None
    from_domain: Optional[str] = None
    from_display_name: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False
    display_name_spoof: bool = False
    details: List[str] = []


class EmailAnalysisResult(BaseModel):
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    headers_found: Dict[str, str] = {}
    extracted_urls: List[str] = []
    url_results: List[URLAnalysisResult] = []
    mismatch: HeaderMismatch
    spf: SPFCheckResult
    dkim: DKIMCheckResult
    dmarc: DMARCCheckResult
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    reasons: List[str] = []
    analyzed_at: str


# --- General / Dashboard Models ---

class RecentScanItem(BaseModel):
    id: str
    type: str  # "url" or "email"
    target: str
    risk_score: int
    risk_level: RiskLevel
    reasons: List[str]
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    version: str
    virustotal_configured: bool
    cache_ttl_seconds: int
