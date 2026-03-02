import httpx
import os
from app.models.schemas import ThreatIndicator

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


def classify_severity(pulse: dict) -> str:
    tags = [t.lower() for t in pulse.get("tags", [])]
    if any(t in tags for t in ["critical", "apt", "ransomware", "zero-day", "zerday"]):
        return "critical"
    elif any(t in tags for t in ["high", "malware", "phishing", "exploit", "backdoor"]):
        return "high"
    elif any(t in tags for t in ["medium", "trojan", "c2", "botnet"]):
        return "medium"
    return "low"


async def get_recent_pulses(limit: int = 10) -> list[ThreatIndicator]:
    if not OTX_API_KEY:
        return get_mock_pulses()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{OTX_BASE_URL}/pulses/subscribed",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            params={"limit": limit},
        )
        response.raise_for_status()
        data = response.json()

    indicators = []
    for pulse in data.get("results", []):
        indicators.append(
            ThreatIndicator(
                id=pulse.get("id", ""),
                name=pulse.get("name", ""),
                description=pulse.get("description", "")[:200] if pulse.get("description") else "",
                created=pulse.get("created"),
                modified=pulse.get("modified"),
                tags=pulse.get("tags", [])[:5],
                indicator_count=pulse.get("indicator_count", 0),
                severity=classify_severity(pulse),
            )
        )
    return indicators


def get_mock_pulses() -> list[ThreatIndicator]:
    """Return mock data when API key is not configured."""
    return [
        ThreatIndicator(id="1", name="APT29 Cozy Bear Campaign", description="Russian APT targeting government and diplomatic networks via spearphishing.", tags=["apt", "russia", "apt29"], severity="critical", indicator_count=145),
        ThreatIndicator(id="2", name="LockBit 3.0 Ransomware", description="New LockBit variant distributed via phishing emails and RDP brute force.", tags=["ransomware", "phishing", "lockbit"], severity="critical", indicator_count=320),
        ThreatIndicator(id="3", name="Log4Shell Active Exploitation", description="Active exploitation of CVE-2021-44228 targeting unpatched Log4j instances.", tags=["exploit", "log4j", "cve-2021-44228"], severity="high", indicator_count=512),
        ThreatIndicator(id="4", name="Emotet Botnet Resurgence", description="Emotet botnet returning with new infrastructure and delivery mechanisms.", tags=["malware", "botnet", "emotet"], severity="high", indicator_count=78),
        ThreatIndicator(id="5", name="Supply Chain Attack - npm Packages", description="Malicious npm packages discovered exfiltrating environment variables.", tags=["supply-chain", "malware"], severity="high", indicator_count=34),
        ThreatIndicator(id="6", name="Credential Stuffing Campaign", description="Large-scale credential stuffing targeting financial institutions.", tags=["phishing", "medium"], severity="medium", indicator_count=22),
        ThreatIndicator(id="7", name="Cobalt Strike Beacon Activity", description="C2 activity detected using Cobalt Strike beacons in enterprise networks.", tags=["c2", "cobalt-strike"], severity="medium", indicator_count=89),
    ]
