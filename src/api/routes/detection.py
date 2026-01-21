"""Detection API routes."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, HttpUrl, field_validator

from src.database.models import get_session
from src.ml.model import PhishingModel
from src.services.detection_service import DetectionService


router = APIRouter()


class URLCheckRequest(BaseModel):
    """Request model for URL check."""
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not v or len(v) < 5:
            raise ValueError('URL must be at least 5 characters')
        if not v.startswith(('http://', 'https://')):
            v = 'https://' + v
        return v


class BatchURLCheckRequest(BaseModel):
    """Request model for batch URL check."""
    urls: List[str]

    @field_validator('urls')
    @classmethod
    def validate_urls(cls, v):
        if len(v) > 100:
            raise ValueError('Maximum 100 URLs per batch')
        return v


class DetectionResponse(BaseModel):
    """Response model for detection result."""
    url: str
    is_phishing: bool
    confidence: float
    ml_score: float
    ml_prediction: bool
    phishtank_match: bool
    phishtank_id: Optional[int] = None
    phishtank_target: Optional[str] = None
    detection_source: str
    features: dict
    checked_at: str
    alert_id: Optional[int] = None


def get_dependencies(request: Request):
    """Get service dependencies."""
    from src.api.app import engine, model, get_session

    if model is None:
        raise HTTPException(
            status_code=503,
            detail="ML model not loaded. Run training script first."
        )

    session = get_session(engine)
    return session, model


@router.post("/detect", response_model=DetectionResponse)
async def detect_url(request: Request, body: URLCheckRequest):
    """
    Check a URL for phishing indicators.

    Combines ML model prediction with PhishTank database lookup.
    Returns confidence score and detailed analysis.
    """
    from src.api.app import engine, model, get_session

    if model is None:
        raise HTTPException(
            status_code=503,
            detail="ML model not loaded. Run 'python scripts/train_model.py' first."
        )

    session = get_session(engine)
    try:
        # Get client IP
        client_ip = request.client.host if request.client else None

        # Perform detection
        service = DetectionService(session, model)
        result = service.detect(body.url, ip_address=client_ip)

        return DetectionResponse(**result.to_dict())
    finally:
        session.close()


@router.post("/detect/batch", response_model=List[DetectionResponse])
async def detect_batch(request: Request, body: BatchURLCheckRequest):
    """
    Check multiple URLs for phishing indicators.

    Maximum 100 URLs per request.
    """
    from src.api.app import engine, model, get_session

    if model is None:
        raise HTTPException(
            status_code=503,
            detail="ML model not loaded. Run 'python scripts/train_model.py' first."
        )

    session = get_session(engine)
    try:
        client_ip = request.client.host if request.client else None
        service = DetectionService(session, model)

        results = []
        for url in body.urls:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            result = service.detect(url, ip_address=client_ip)
            results.append(DetectionResponse(**result.to_dict()))

        return results
    finally:
        session.close()


@router.get("/detect/history")
async def get_history(
    request: Request,
    limit: int = 50,
    phishing_only: bool = False
):
    """Get URL check history."""
    from src.api.app import engine, model, get_session

    session = get_session(engine)
    try:
        if model is None:
            # Return empty list if model not loaded
            return []

        service = DetectionService(session, model)

        if phishing_only:
            checks = service.get_phishing_detections(days=30)
        else:
            checks = service.get_recent_checks(limit)

        return [
            {
                "id": check.id,
                "url": check.url,
                "is_phishing": check.is_phishing,
                "confidence": check.confidence,
                "ml_score": check.ml_score,
                "detection_source": check.detection_source,
                "phishtank_target": check.phishtank_target,
                "checked_at": check.checked_at.isoformat()
            }
            for check in checks
        ]
    finally:
        session.close()
