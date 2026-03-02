from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from app.routers import ips, threats

load_dotenv()

app = FastAPI(
    title="ThreatWatch",
    description="Threat Intelligence Dashboard — powered by AbuseIPDB & AlienVault OTX",
    version="1.0.0",
)

app.include_router(ips.router, prefix="/api")
app.include_router(threats.router, prefix="/api")

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/")
async def root():
    return FileResponse("app/static/index.html")
