from pydantic import BaseModel, Field

# This defines exactly what the user must send to your API
class LinkAnalysisRequest(BaseModel):
    url: str = Field(..., example="https://amaz0n-security-update.com/login")

# This defines exactly what your API promises to return
class LinkAnalysisResponse(BaseModel):
    url: str
    status: str
    threat_score: float
    verdict: str
    details: dict