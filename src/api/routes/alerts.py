"""Alert API routes."""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.services.alert_service import AlertService


router = APIRouter()


class AlertUpdateRequest(BaseModel):
    """Request model for alert update."""
    status: str  # 'acknowledged', 'resolved', 'false_positive'
    resolved_by: Optional[str] = None


class AlertResponse(BaseModel):
    """Response model for alert."""
    id: int
    url_check_id: int
    severity: str
    status: str
    title: str
    description: Optional[str] = None
    url: Optional[str] = None
    confidence: Optional[float] = None
    target: Optional[str] = None
    created_at: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None


@router.get("/alerts", response_model=List[AlertResponse])
async def list_alerts(
    request: Request,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    """
    List all alerts with optional filtering.

    Parameters:
    - status: Filter by status (new, acknowledged, resolved, false_positive)
    - severity: Filter by severity (low, medium, high, critical)
    - limit: Maximum number of alerts to return
    - offset: Number of alerts to skip
    """
    from src.api.app import engine, get_session

    session = get_session(engine)
    try:
        service = AlertService(session)
        alerts = service.get_alerts(
            status=status,
            severity=severity,
            limit=limit,
            offset=offset
        )

        return [
            AlertResponse(**service.alert_to_dict(alert))
            for alert in alerts
        ]
    finally:
        session.close()


@router.get("/alerts/new", response_model=List[AlertResponse])
async def get_new_alerts(request: Request, limit: int = 10):
    """Get new unacknowledged alerts."""
    from src.api.app import engine, get_session

    session = get_session(engine)
    try:
        service = AlertService(session)
        alerts = service.get_new_alerts(limit)

        return [
            AlertResponse(**service.alert_to_dict(alert))
            for alert in alerts
        ]
    finally:
        session.close()


@router.get("/alerts/counts")
async def get_alert_counts(request: Request):
    """Get counts of alerts by status."""
    from src.api.app import engine, get_session

    session = get_session(engine)
    try:
        service = AlertService(session)
        return service.get_alert_counts()
    finally:
        session.close()


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(request: Request, alert_id: int):
    """Get a specific alert by ID."""
    from src.api.app import engine, get_session

    session = get_session(engine)
    try:
        service = AlertService(session)
        alert = service.get_alert(alert_id)

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        return AlertResponse(**service.alert_to_dict(alert))
    finally:
        session.close()


@router.patch("/alerts/{alert_id}", response_model=AlertResponse)
async def update_alert(request: Request, alert_id: int, body: AlertUpdateRequest):
    """
    Update an alert's status.

    Valid status values:
    - acknowledged: Mark alert as seen
    - resolved: Mark alert as resolved
    - false_positive: Mark alert as false positive
    """
    from src.api.app import engine, get_session

    valid_statuses = {'acknowledged', 'resolved', 'false_positive'}
    if body.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )

    session = get_session(engine)
    try:
        service = AlertService(session)

        if body.status == 'acknowledged':
            alert = service.acknowledge_alert(alert_id)
        elif body.status == 'resolved':
            alert = service.resolve_alert(alert_id, body.resolved_by)
        else:  # false_positive
            alert = service.mark_false_positive(alert_id, body.resolved_by)

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        return AlertResponse(**service.alert_to_dict(alert))
    finally:
        session.close()
