from fastapi import APIRouter, HTTPException
from app.services import otx
from app.models.schemas import ThreatIndicator
from typing import List

router = APIRouter(tags=["Threats"])


@router.get("/threats/pulses", response_model=List[ThreatIndicator])
async def get_pulses(limit: int = 10):
    try:
        return await otx.get_recent_pulses(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
