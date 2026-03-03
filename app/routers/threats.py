import uuid

from fastapi import APIRouter

from app.feeds.abuseipdb import fetch_malicious_ips
from app.feeds.otx import fetch_otx_pulses
from app.mappers.killchain import map_to_killchain
from app.mappers.mitre import map_to_mitre

router = APIRouter()


@router.get("/threats")
async def get_threats():
    results = []

    ips = await fetch_malicious_ips()
    for ip in ips:
        mitre = map_to_mitre(ip)
        results.append({
            "id": str(uuid.uuid4()),
            "ip_address": ip.get("ipAddress"),
            "indicator_type": "ip",
            "severity": "critical" if ip.get("abuseConfidenceScore", 0) >= 90 else "high",
            "confidence_score": ip.get("abuseConfidenceScore", 0),
            "country_code": ip.get("countryCode"),
            "kill_chain_stage": map_to_killchain(ip),
            "mitre_tactic": mitre["tactic"],
            "mitre_technique": mitre["technique"],
            "mitre_technique_id": mitre["technique_id"],
            "source": "AbuseIPDB",
            "tags": [],
            "reported_at": ip.get("lastReportedAt"),
            "raw": ip,
        })

    pulses = await fetch_otx_pulses()
    for pulse in pulses:
        mitre = map_to_mitre(pulse)
        results.append({
            "id": str(uuid.uuid4()),
            "ip_address": None,
            "indicator_type": "pulse",
            "severity": "high",
            "confidence_score": 75,
            "country_code": None,
            "kill_chain_stage": map_to_killchain(pulse),
            "mitre_tactic": mitre["tactic"],
            "mitre_technique": mitre["technique"],
            "mitre_technique_id": mitre["technique_id"],
            "source": "AlienVault OTX",
            "tags": pulse.get("tags", []),
            "reported_at": "",
            "raw": pulse,
        })

    return results


@router.get("/threats/summary")
async def get_summary():
    threats = await get_threats()
    summary = {"by_severity": {}, "by_kill_chain": {}, "by_mitre_tactic": {}}
    for t in threats:
        s = t["severity"]
        k = t["kill_chain_stage"]
        m = t["mitre_tactic"]
        summary["by_severity"][s] = summary["by_severity"].get(s, 0) + 1
        summary["by_kill_chain"][k] = summary["by_kill_chain"].get(k, 0) + 1
        summary["by_mitre_tactic"][m] = summary["by_mitre_tactic"].get(m, 0) + 1
    return summary


@router.get("/threats/killchain")
async def get_killchain():
    threats = await get_threats()
    stages = [
        "Reconnaissance",
        "Weaponization",
        "Delivery",
        "Exploitation",
        "Installation",
        "Command & Control",
        "Actions on Objectives",
    ]
    counts = {s: 0 for s in stages}
    for t in threats:
        stage = t["kill_chain_stage"]
        if stage in counts:
            counts[stage] += 1
    return counts


@router.get("/threats/mitre")
async def get_mitre():
    threats = await get_threats()
    tactics = {}
    for t in threats:
        tactic = t["mitre_tactic"]
        tactics[tactic] = tactics.get(tactic, 0) + 1
    return tactics
