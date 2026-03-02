from fastapi import APIRouter, HTTPException
from app.services import abuseipdb
from app.models.schemas import MaliciousIP
from typing import List

router = APIRouter(tags=["IPs"])


@router.get("/ips/blacklist", response_model=List[MaliciousIP])
async def get_blacklist(limit: int = 25):
    try:
        return await abuseipdb.get_blacklist(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ips/check/{ip}", response_model=MaliciousIP)
async def check_ip(ip: str):
    try:
        return await abuseipdb.check_ip(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
