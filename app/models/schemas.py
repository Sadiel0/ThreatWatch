from pydantic import BaseModel
from typing import Optional, List


class MaliciousIP(BaseModel):
    ip: str
    abuse_confidence_score: int
    country_code: Optional[str] = None
    isp: Optional[str] = None
    last_reported: Optional[str] = None
    total_reports: int = 0
    severity: str = "low"


class ThreatIndicator(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    tags: List[str] = []
    severity: str = "medium"
    indicator_count: int = 0
    source: str = "AlienVault OTX"
