"""Statistics API routes."""
from typing import List
from fastapi import APIRouter, Request
from pydantic import BaseModel

from src.database.repository import StatisticsRepository, PhishTankRepository


router = APIRouter()


class DashboardStats(BaseModel):
    """Dashboard statistics response."""
    today_checks: int
    today_phishing: int
    week_checks: int
    week_phishing: int
    new_alerts: int
    detection_rate: float
    model_loaded: bool
    model_version: str = ""
    model_accuracy: float = 0.0
    phishtank_entries: int = 0


class DailyTrend(BaseModel):
    """Daily trend data point."""
    date: str
    total: int
    phishing: int


class TargetStats(BaseModel):
    """Target brand statistics."""
    target: str
    count: int
    percentage: float


@router.get("/stats/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(request: Request):
    """Get dashboard summary statistics."""
    from src.api.app import engine, model, get_session

    session = get_session(engine)
    try:
        stats_repo = StatisticsRepository(session)
        phishtank_repo = PhishTankRepository(session)

        stats = stats_repo.get_dashboard_stats()
        phishtank_count = phishtank_repo.count()

        model_loaded = model is not None
        model_version = model.model_version if model else ""
        model_accuracy = model.metrics.get('accuracy', 0) if model else 0

        return DashboardStats(
            today_checks=stats['today_checks'],
            today_phishing=stats['today_phishing'],
            week_checks=stats['week_checks'],
            week_phishing=stats['week_phishing'],
            new_alerts=stats['new_alerts'],
            detection_rate=stats['detection_rate'],
            model_loaded=model_loaded,
            model_version=model_version,
            model_accuracy=model_accuracy,
            phishtank_entries=phishtank_count
        )
    finally:
        session.close()


@router.get("/stats/daily", response_model=List[DailyTrend])
async def get_daily_trend(request: Request, days: int = 7):
    """Get daily detection trend for the last N days."""
    from src.api.app import engine, get_session

    session = get_session(engine)
    try:
        stats_repo = StatisticsRepository(session)
        trend = stats_repo.get_daily_trend(days)

        return [DailyTrend(**day) for day in trend]
    finally:
        session.close()


@router.get("/stats/targets", response_model=List[TargetStats])
async def get_top_targets(request: Request, limit: int = 10):
    """Get top phishing targets from PhishTank data."""
    from src.api.app import engine, get_session

    session = get_session(engine)
    try:
        phishtank_repo = PhishTankRepository(session)
        targets = phishtank_repo.get_target_distribution(limit)

        total = sum(count for _, count in targets)

        return [
            TargetStats(
                target=target,
                count=count,
                percentage=round(count / total * 100, 1) if total > 0 else 0
            )
            for target, count in targets
        ]
    finally:
        session.close()
