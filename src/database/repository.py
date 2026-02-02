"""Database repository for CRUD operations."""
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from .models import URLCheck, Alert, PhishTankEntry, DailyStatistics, MLModel


class URLCheckRepository:
    """Repository for URL check operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, url_check: URLCheck) -> URLCheck:
        """Create a new URL check record."""
        self.session.add(url_check)
        self.session.commit()
        self.session.refresh(url_check)
        return url_check

    def get_by_id(self, check_id: int) -> Optional[URLCheck]:
        """Get URL check by ID."""
        return self.session.query(URLCheck).filter(URLCheck.id == check_id).first()

    def get_by_url_hash(self, url_hash: str) -> Optional[URLCheck]:
        """Get most recent URL check by URL hash."""
        return self.session.query(URLCheck).filter(
            URLCheck.url_hash == url_hash
        ).order_by(desc(URLCheck.checked_at)).first()

    def get_recent(self, limit: int = 50) -> List[URLCheck]:
        """Get recent URL checks."""
        return self.session.query(URLCheck).order_by(
            desc(URLCheck.checked_at)
        ).limit(limit).all()

    def get_phishing_detections(self, days: int = 7) -> List[URLCheck]:
        """Get phishing detections from last N days."""
        since = datetime.utcnow() - timedelta(days=days)
        return self.session.query(URLCheck).filter(
            URLCheck.is_phishing == True,
            URLCheck.checked_at >= since
        ).order_by(desc(URLCheck.checked_at)).all()


class AlertRepository:
    """Repository for alert operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, alert: Alert) -> Alert:
        """Create a new alert."""
        self.session.add(alert)
        self.session.commit()
        self.session.refresh(alert)
        return alert

    def get_by_id(self, alert_id: int) -> Optional[Alert]:
        """Get alert by ID."""
        return self.session.query(Alert).filter(Alert.id == alert_id).first()

    def get_all(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Alert]:
        """Get alerts with filtering."""
        query = self.session.query(Alert)

        if status:
            query = query.filter(Alert.status == status)
        if severity:
            query = query.filter(Alert.severity == severity)

        return query.order_by(desc(Alert.created_at)).offset(offset).limit(limit).all()

    def get_new_alerts(self, limit: int = 10) -> List[Alert]:
        """Get new unacknowledged alerts."""
        return self.session.query(Alert).filter(
            Alert.status == "new"
        ).order_by(desc(Alert.created_at)).limit(limit).all()

    def update_status(
        self,
        alert_id: int,
        status: str,
        resolved_by: Optional[str] = None
    ) -> Optional[Alert]:
        """Update alert status."""
        alert = self.get_by_id(alert_id)
        if alert:
            alert.status = status
            if status == "acknowledged":
                alert.acknowledged_at = datetime.utcnow()
            elif status in ("resolved", "false_positive"):
                alert.resolved_at = datetime.utcnow()
                alert.resolved_by = resolved_by
            self.session.commit()
            self.session.refresh(alert)
        return alert

    def count_by_status(self) -> dict:
        """Count alerts by status."""
        results = self.session.query(
            Alert.status, func.count(Alert.id)
        ).group_by(Alert.status).all()
        return {status: count for status, count in results}


class PhishTankRepository:
    """Repository for PhishTank entries."""

    def __init__(self, session: Session):
        self.session = session

    def create_or_update(self, entry: PhishTankEntry) -> PhishTankEntry:
        """Create or update a PhishTank entry."""
        existing = self.session.query(PhishTankEntry).filter(
            PhishTankEntry.phish_id == entry.phish_id
        ).first()

        if existing:
            existing.url = entry.url
            existing.url_hash = entry.url_hash
            existing.target = entry.target
            existing.online = entry.online
            existing.synced_at = datetime.utcnow()
            self.session.commit()
            return existing
        else:
            self.session.add(entry)
            self.session.commit()
            self.session.refresh(entry)
            return entry

    def bulk_insert(self, entries: List[PhishTankEntry]) -> int:
        """Bulk insert PhishTank entries."""
        self.session.bulk_save_objects(entries)
        self.session.commit()
        return len(entries)

    def find_by_url_hash(self, url_hash: str) -> Optional[PhishTankEntry]:
        """Find entry by URL hash."""
        return self.session.query(PhishTankEntry).filter(
            PhishTankEntry.url_hash == url_hash
        ).first()

    def find_by_url(self, url: str) -> Optional[PhishTankEntry]:
        """Find entry by exact URL match."""
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        return self.find_by_url_hash(url_hash)

    def count(self) -> int:
        """Count total entries."""
        return self.session.query(func.count(PhishTankEntry.id)).scalar()

    def get_target_distribution(self, limit: int = 10) -> List[tuple]:
        """Get distribution of phishing targets."""
        return self.session.query(
            PhishTankEntry.target, func.count(PhishTankEntry.id)
        ).filter(
            PhishTankEntry.target.isnot(None)
        ).group_by(PhishTankEntry.target).order_by(
            desc(func.count(PhishTankEntry.id))
        ).limit(limit).all()


class StatisticsRepository:
    """Repository for statistics."""

    def __init__(self, session: Session):
        self.session = session

    def get_dashboard_stats(self) -> dict:
        """Get dashboard statistics."""
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        week_ago = today - timedelta(days=7)

        # Today's stats
        today_checks = self.session.query(func.count(URLCheck.id)).filter(
            URLCheck.checked_at >= today
        ).scalar() or 0

        today_phishing = self.session.query(func.count(URLCheck.id)).filter(
            URLCheck.checked_at >= today,
            URLCheck.is_phishing == True
        ).scalar() or 0

        # Week stats
        week_checks = self.session.query(func.count(URLCheck.id)).filter(
            URLCheck.checked_at >= week_ago
        ).scalar() or 0

        week_phishing = self.session.query(func.count(URLCheck.id)).filter(
            URLCheck.checked_at >= week_ago,
            URLCheck.is_phishing == True
        ).scalar() or 0

        # New alerts
        new_alerts = self.session.query(func.count(Alert.id)).filter(
            Alert.status == "new"
        ).scalar() or 0

        # Detection rate
        detection_rate = (week_phishing / week_checks * 100) if week_checks > 0 else 0

        return {
            "today_checks": today_checks,
            "today_phishing": today_phishing,
            "week_checks": week_checks,
            "week_phishing": week_phishing,
            "new_alerts": new_alerts,
            "detection_rate": round(detection_rate, 2)
        }

    def get_daily_trend(self, days: int = 7) -> List[dict]:
        """Get daily detection trend."""
        results = []
        for i in range(days - 1, -1, -1):
            day = datetime.utcnow().replace(
                hour=0, minute=0, second=0, microsecond=0
            ) - timedelta(days=i)
            next_day = day + timedelta(days=1)

            total = self.session.query(func.count(URLCheck.id)).filter(
                URLCheck.checked_at >= day,
                URLCheck.checked_at < next_day
            ).scalar() or 0

            phishing = self.session.query(func.count(URLCheck.id)).filter(
                URLCheck.checked_at >= day,
                URLCheck.checked_at < next_day,
                URLCheck.is_phishing == True
            ).scalar() or 0

            results.append({
                "date": day.strftime("%Y-%m-%d"),
                "total": total,
                "phishing": phishing
            })

        return results
