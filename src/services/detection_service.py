"""Detection service combining ML model and PhishTank database."""
import hashlib
from datetime import datetime
from typing import Optional, Tuple
from dataclasses import dataclass, asdict

from sqlalchemy.orm import Session

from src.ml.model import PhishingModel
from src.ml.feature_extractor import URLFeatures
from src.database.models import URLCheck, Alert, PhishTankEntry
from src.database.repository import URLCheckRepository, AlertRepository, PhishTankRepository
from config.settings import settings


@dataclass
class DetectionResult:
    """Result of URL detection."""
    url: str
    is_phishing: bool
    confidence: float
    ml_score: float
    ml_prediction: bool
    phishtank_match: bool
    phishtank_id: Optional[int]
    phishtank_target: Optional[str]
    detection_source: str  # 'ml', 'database', 'both'
    features: dict
    checked_at: datetime
    alert_id: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = asdict(self)
        result['checked_at'] = self.checked_at.isoformat()
        return result


class DetectionService:
    """Service for detecting phishing URLs."""

    def __init__(self, session: Session, model: PhishingModel):
        self.session = session
        self.model = model
        self.url_check_repo = URLCheckRepository(session)
        self.alert_repo = AlertRepository(session)
        self.phishtank_repo = PhishTankRepository(session)

    def detect(self, url: str, ip_address: Optional[str] = None) -> DetectionResult:
        """
        Detect if a URL is phishing.

        Combines ML model prediction with PhishTank database lookup.

        Args:
            url: URL to check
            ip_address: IP address of requester (optional)

        Returns:
            DetectionResult with all detection details
        """
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        checked_at = datetime.utcnow()

        # Get ML prediction
        ml_prediction, ml_score, features = self.model.predict_with_features(url)

        # Check PhishTank database
        phishtank_entry = self.phishtank_repo.find_by_url_hash(url_hash)
        phishtank_match = phishtank_entry is not None

        # Combine results
        is_phishing, confidence, detection_source = self._combine_results(
            ml_prediction, ml_score, phishtank_match
        )

        # Create detection result
        result = DetectionResult(
            url=url,
            is_phishing=is_phishing,
            confidence=confidence,
            ml_score=ml_score,
            ml_prediction=ml_prediction,
            phishtank_match=phishtank_match,
            phishtank_id=phishtank_entry.phish_id if phishtank_entry else None,
            phishtank_target=phishtank_entry.target if phishtank_entry else None,
            detection_source=detection_source,
            features=features.to_dict(),
            checked_at=checked_at
        )

        # Store URL check
        url_check = self._store_url_check(result, url_hash, ip_address)

        # Generate alert if phishing
        if is_phishing:
            alert = self._generate_alert(url_check, result)
            result.alert_id = alert.id

        return result

    def _combine_results(
        self,
        ml_prediction: bool,
        ml_score: float,
        phishtank_match: bool
    ) -> Tuple[bool, float, str]:
        """
        Combine ML and PhishTank results.

        Priority Logic:
        - PhishTank match = definite phishing (confidence 1.0)
        - High ML score (>0.8) = likely phishing
        - Moderate ML score (0.5-0.8) = suspicious
        """
        if phishtank_match:
            # Found in PhishTank database
            if ml_prediction:
                return True, 1.0, "both"
            else:
                return True, 1.0, "database"

        if ml_prediction:
            # ML says phishing, not in PhishTank
            confidence = min(0.95, ml_score)  # Cap at 95% without DB verification
            return True, confidence, "ml"

        # Not phishing
        confidence = 1.0 - ml_score
        return False, confidence, "ml"

    def _store_url_check(
        self,
        result: DetectionResult,
        url_hash: str,
        ip_address: Optional[str]
    ) -> URLCheck:
        """Store URL check in database."""
        url_check = URLCheck(
            url=result.url,
            url_hash=url_hash,
            ml_score=result.ml_score,
            ml_prediction=result.ml_prediction,
            ml_model_version=self.model.model_version,
            phishtank_match=result.phishtank_match,
            phishtank_id=result.phishtank_id,
            phishtank_target=result.phishtank_target,
            is_phishing=result.is_phishing,
            confidence=result.confidence,
            detection_source=result.detection_source,
            features=result.features,
            checked_at=result.checked_at,
            ip_address=ip_address
        )
        return self.url_check_repo.create(url_check)

    def _generate_alert(self, url_check: URLCheck, result: DetectionResult) -> Alert:
        """Generate alert for detected phishing URL."""
        # Determine severity
        severity = self._determine_severity(result.confidence, result.phishtank_match)

        # Create title
        if result.phishtank_target:
            title = f"Phishing URL detected targeting {result.phishtank_target}"
        else:
            title = "Potential phishing URL detected"

        # Create description
        description = self._create_alert_description(result)

        alert = Alert(
            url_check_id=url_check.id,
            severity=severity,
            status="new",
            title=title,
            description=description
        )
        return self.alert_repo.create(alert)

    def _determine_severity(self, confidence: float, phishtank_match: bool) -> str:
        """Determine alert severity based on confidence and source."""
        if phishtank_match or confidence >= settings.ALERT_CRITICAL_THRESHOLD:
            return "critical"
        elif confidence >= settings.ALERT_HIGH_THRESHOLD:
            return "high"
        elif confidence >= settings.ALERT_MEDIUM_THRESHOLD:
            return "medium"
        else:
            return "low"

    def _create_alert_description(self, result: DetectionResult) -> str:
        """Create detailed alert description."""
        lines = [
            f"URL: {result.url}",
            f"Confidence: {result.confidence:.1%}",
            f"Detection Source: {result.detection_source}",
            f"ML Score: {result.ml_score:.1%}",
        ]

        if result.phishtank_match:
            lines.append(f"PhishTank ID: {result.phishtank_id}")
            if result.phishtank_target:
                lines.append(f"Target Brand: {result.phishtank_target}")

        # Add suspicious feature highlights
        features = result.features
        suspicious = []

        if features.get('has_ip_address'):
            suspicious.append("Contains IP address")
        if features.get('is_suspicious_tld'):
            suspicious.append("Suspicious TLD")
        if features.get('brand_mismatch'):
            suspicious.append("Brand name mismatch")
        if features.get('has_suspicious_path'):
            suspicious.append("Suspicious path keywords")
        if features.get('has_at_symbol'):
            suspicious.append("Contains @ symbol")
        if features.get('has_punycode'):
            suspicious.append("Uses punycode (IDN)")

        if suspicious:
            lines.append(f"\nSuspicious Indicators: {', '.join(suspicious)}")

        return "\n".join(lines)

    def get_recent_checks(self, limit: int = 50):
        """Get recent URL checks."""
        return self.url_check_repo.get_recent(limit)

    def get_phishing_detections(self, days: int = 7):
        """Get phishing detections from last N days."""
        return self.url_check_repo.get_phishing_detections(days)
