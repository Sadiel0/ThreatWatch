import asyncio
import logging
import os
from datetime import datetime, timedelta

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

_cache: dict = {"data": [], "fetched_at": None}


async def fetch_otx_pulses() -> list[dict]:
    if _cache["fetched_at"] is not None and datetime.utcnow() - _cache["fetched_at"] < timedelta(hours=24):
        logger.info("OTX: returning cached data (%d pulses)", len(_cache["data"]))
        return _cache["data"]

    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        logger.error("OTX_API_KEY is not set")
        return []

    headers = {
        "X-OTX-API-KEY": api_key,
    }
    params = {
        "limit": 20,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(OTX_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            result = [
                {
                    "name": pulse.get("name"),
                    "description": pulse.get("description"),
                    "indicators": pulse.get("indicators", []),
                    "tags": pulse.get("tags", []),
                    "adversary": pulse.get("adversary"),
                }
                for pulse in data.get("results", [])
            ]
            _cache["data"] = result
            _cache["fetched_at"] = datetime.utcnow()
            return result
    except httpx.HTTPStatusError as e:
        logger.error("OTX request failed: %s %s", e.response.status_code, e.response.text)
        return []
    except httpx.RequestError as e:
        logger.error("OTX connection error: %s", e)
        return []


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(fetch_otx_pulses())
    print(f"Fetched {len(results)} pulses")
    for pulse in results[:3]:
        print({k: v for k, v in pulse.items() if k != "indicators"})
        print(f"  indicators: {len(pulse['indicators'])}")
