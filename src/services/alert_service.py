"""Alert management service."""
from typing import List, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from src.database.models import Alert
from src.database.repository import AlertRepository


class AlertService:
    """Service for managing alerts."""

    def __init__(self, session: Session):
        self.session = session
        self.alert_repo = AlertRepository(session)

    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Alert]:
        """Get alerts with filtering."""
        return self.alert_repo.get_all(
            status=status,
            severity=severity,
            limit=limit,
            offset=offset
        )

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Get alert by ID."""
        return self.alert_repo.get_by_id(alert_id)

    def get_new_alerts(self, limit: int = 10) -> List[Alert]:
        """Get new unacknowledged alerts."""
        return self.alert_repo.get_new_alerts(limit)

    def acknowledge_alert(self, alert_id: int) -> Optional[Alert]:
        """Acknowledge an alert."""
        return self.alert_repo.update_status(alert_id, "acknowledged")

    def resolve_alert(
        self,
        alert_id: int,
        resolved_by: Optional[str] = None
    ) -> Optional[Alert]:
        """Resolve an alert."""
        return self.alert_repo.update_status(
            alert_id, "resolved", resolved_by=resolved_by
        )

    def mark_false_positive(
        self,
        alert_id: int,
        resolved_by: Optional[str] = None
    ) -> Optional[Alert]:
        """Mark alert as false positive."""
        return self.alert_repo.update_status(
            alert_id, "false_positive", resolved_by=resolved_by
        )

    def get_alert_counts(self) -> dict:
        """Get counts of alerts by status."""
        return self.alert_repo.count_by_status()

    def alert_to_dict(self, alert: Alert) -> dict:
        """Convert alert to dictionary."""
        return {
            "id": alert.id,
            "url_check_id": alert.url_check_id,
            "severity": alert.severity,
            "status": alert.status,
            "title": alert.title,
            "description": alert.description,
            "url": alert.url_check.url if alert.url_check else None,
            "confidence": alert.url_check.confidence if alert.url_check else None,
            "target": alert.url_check.phishtank_target if alert.url_check else None,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "resolved_by": alert.resolved_by
        }
