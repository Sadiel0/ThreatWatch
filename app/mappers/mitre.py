from typing import TypedDict

MITRE_RULES: list[tuple[list[str], dict]] = [
    (
        ["brute force", "brute-force", "password spray", "credential stuffing"],
        {"tactic": "Credential Access", "technique": "Brute Force", "technique_id": "T1110"},
    ),
    (
        ["c2", "c&c", "botnet", "command and control", "beacon"],
        {"tactic": "Command and Control", "technique": "Application Layer Protocol", "technique_id": "T1071"},
    ),
    (
        ["scan", "scanning", "active scan", "port scan", "enumerat"],
        {"tactic": "Reconnaissance", "technique": "Active Scanning", "technique_id": "T1595"},
    ),
    (
        ["malware", "rat", "trojan", "remote access trojan"],
        {"tactic": "Execution", "technique": "User Execution", "technique_id": "T1204"},
    ),
    (
        ["phishing", "webdav", "lnk", "delivery", "spear", "email attachment"],
        {"tactic": "Initial Access", "technique": "Phishing", "technique_id": "T1566"},
    ),
    (
        ["webshell", "exploit", "cve-", "rce", "server software"],
        {"tactic": "Persistence", "technique": "Server Software Component", "technique_id": "T1505"},
    ),
    (
        ["lateral movement", "remote service", "pass the hash", "pass the ticket"],
        {"tactic": "Lateral Movement", "technique": "Remote Services", "technique_id": "T1021"},
    ),
]

_DEFAULT = {"tactic": "Unknown", "technique": "Unknown", "technique_id": "T0000"}


def _tokens(indicator: dict) -> str:
    parts = [
        " ".join(indicator.get("tags", [])),
        indicator.get("description", ""),
        indicator.get("name", ""),
    ]
    return " ".join(parts).lower()


def map_to_mitre(indicator: dict) -> dict:
    text = _tokens(indicator)
    for keywords, mapping in MITRE_RULES:
        if any(kw in text for kw in keywords):
            return mapping
    return _DEFAULT


if __name__ == "__main__":
    sample = {
        "name": "Abusing Windows File Explorer and WebDAV for Malware Delivery",
        "tags": ["malware delivery", "phishing", "webdav", "lnk file", "remote access trojan"],
        "description": "Threat actors exploiting WebDAV to deliver RATs via phishing",
    }
    print(map_to_mitre(sample))
