from fastapi import FastAPI
from pydantic import BaseModel

from core.orchestrator import process_alert


app = FastAPI(
    title="SentinelFlow AI API",
    description="Governed SOC Agentic AI Backend",
    version="1.0"
)


class AlertRequest(BaseModel):
    alert_id: str


@app.get("/")
def root():
    return {
        "system": "SentinelFlow AI",
        "status": "running",
        "description": "Governed Agentic SOC Decision Support"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/analyse")
def analyse_alert(request: AlertRequest):
    result = process_alert(request.alert_id)

    return result