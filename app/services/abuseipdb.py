import httpx
import os
from app.models.schemas import MaliciousIP

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"


def get_severity(score: int) -> str:
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    return "low"


async def get_blacklist(limit: int = 25) -> list[MaliciousIP]:
    if not ABUSEIPDB_API_KEY:
        return get_mock_ips()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{ABUSEIPDB_BASE_URL}/blacklist",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"limit": limit, "confidenceMinimum": 90},
        )
        response.raise_for_status()
        data = response.json()

    ips = []
    for item in data.get("data", []):
        score = item.get("abuseConfidenceScore", 0)
        ips.append(
            MaliciousIP(
                ip=item.get("ipAddress", ""),
                abuse_confidence_score=score,
                country_code=item.get("countryCode"),
                isp=item.get("isp"),
                last_reported=item.get("lastReportedAt"),
                total_reports=item.get("numReports", 0),
                severity=get_severity(score),
            )
        )
    return ips


async def check_ip(ip: str) -> MaliciousIP:
    if not ABUSEIPDB_API_KEY:
        return MaliciousIP(ip=ip, abuse_confidence_score=0, severity="unknown")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        response.raise_for_status()
        data = response.json().get("data", {})

    score = data.get("abuseConfidenceScore", 0)
    return MaliciousIP(
        ip=ip,
        abuse_confidence_score=score,
        country_code=data.get("countryCode"),
        isp=data.get("isp"),
        last_reported=data.get("lastReportedAt"),
        total_reports=data.get("totalReports", 0),
        severity=get_severity(score),
    )


def get_mock_ips() -> list[MaliciousIP]:
    """Return mock data when API key is not configured."""
    return [
        MaliciousIP(ip="192.168.1.100", abuse_confidence_score=98, country_code="CN", isp="China Telecom", total_reports=312, severity="critical"),
        MaliciousIP(ip="185.220.101.45", abuse_confidence_score=95, country_code="DE", isp="Tor Exit Node", total_reports=210, severity="critical"),
        MaliciousIP(ip="45.33.32.156", abuse_confidence_score=82, country_code="US", isp="Linode LLC", total_reports=87, severity="critical"),
        MaliciousIP(ip="103.21.244.0", abuse_confidence_score=71, country_code="RU", isp="Mock ISP RU", total_reports=54, severity="high"),
        MaliciousIP(ip="198.51.100.1", abuse_confidence_score=55, country_code="BR", isp="CLARO S.A.", total_reports=23, severity="high"),
        MaliciousIP(ip="203.0.113.50", abuse_confidence_score=38, country_code="KP", isp="Star JV", total_reports=12, severity="medium"),
        MaliciousIP(ip="172.16.0.22", abuse_confidence_score=20, country_code="IN", isp="BSNL India", total_reports=6, severity="low"),
    ]
