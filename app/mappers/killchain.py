STAGES = [
    ("Reconnaissance",          ["scan", "recon", "enumerat", "fingerprint", "osint", "discovery"]),
    ("Weaponization",           ["exploit kit", "builder", "dropper", "packer", "weaponiz", "payload creat"]),
    ("Delivery",                ["phishing", "webdav", "lnk", "email", "attachment", "delivery", "spear", "malware delivery"]),
    ("Exploitation",            ["exploit", "cve-", "vulnerability", "overflow", "rce", "injection"]),
    ("Installation",            ["install", "trojan", "rat", "remote access", "implant", "backdoor", "malware", "dropper"]),
    ("Command & Control",       ["c2", "c&c", "botnet", "command and control", "beacon", "cobaltstrike", "cobalt strike"]),
    ("Actions on Objectives",   ["exfiltrat", "ransomware", "encrypt", "lateral movement", "credential", "data theft", "destruction"]),
]


def _tokens(indicator: dict) -> str:
    parts = [
        " ".join(indicator.get("tags", [])),
        indicator.get("description", ""),
        indicator.get("name", ""),
        indicator.get("type", ""),
    ]
    return " ".join(parts).lower()


def map_to_killchain(indicator: dict) -> str:
    text = _tokens(indicator)
    for stage, keywords in STAGES:
        if any(kw in text for kw in keywords):
            return stage
    return "Unknown"


if __name__ == "__main__":
    sample = {
        "name": "Abusing Windows File Explorer and WebDAV for Malware Delivery",
        "tags": ["malware delivery", "phishing", "webdav", "lnk file", "remote access trojan"],
        "description": "Threat actors exploiting WebDAV to deliver RATs via phishing",
    }
    print(map_to_killchain(sample))
