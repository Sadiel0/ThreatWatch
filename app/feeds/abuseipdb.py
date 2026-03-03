import asyncio
import logging
import os
from datetime import datetime, timedelta

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"

_cache: dict = {"data": [], "fetched_at": None}


async def fetch_malicious_ips() -> list[dict]:
    if _cache["fetched_at"] is not None and datetime.utcnow() - _cache["fetched_at"] < timedelta(hours=24):
        logger.info("AbuseIPDB: returning cached data (%d IPs)", len(_cache["data"]))
        return _cache["data"]

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.error("ABUSEIPDB_API_KEY is not set")
        return []

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": 90,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(ABUSEIPDB_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            result = [
                {
                    "ipAddress": entry.get("ipAddress"),
                    "abuseConfidenceScore": entry.get("abuseConfidenceScore"),
                    "countryCode": entry.get("countryCode"),
                    "lastReportedAt": entry.get("lastReportedAt"),
                }
                for entry in data.get("data", [])
            ]
            _cache["data"] = result
            _cache["fetched_at"] = datetime.utcnow()
            return result
    except httpx.HTTPStatusError as e:
        logger.error("AbuseIPDB request failed: %s %s", e.response.status_code, e.response.text)
        return []
    except httpx.RequestError as e:
        logger.error("AbuseIPDB connection error: %s", e)
        return []


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(fetch_malicious_ips())
    print(f"Fetched {len(results)} IPs")
    for ip in results[:5]:
        print(ip)
