"""ML Model for phishing URL detection."""
import joblib
import numpy as np
from typing import Optional, Tuple, List, Dict, Any
from pathlib import Path
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix
)
from sklearn.preprocessing import StandardScaler

from .feature_extractor import FeatureExtractor, URLFeatures


class PhishingModel:
    """Phishing detection ML model wrapper."""

    def __init__(self, model_path: Optional[Path] = None):
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_extractor = FeatureExtractor()
        self.feature_names: List[str] = []
        self.model_version: str = ""
        self.metrics: Dict[str, float] = {}

        if model_path and Path(model_path).exists():
            self.load(model_path)

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        random_state: int = 42
    ) -> Dict[str, Any]:
        """
        Train the phishing detection model.

        Args:
            X: Feature matrix
            y: Labels (1 for phishing, 0 for legitimate)
            test_size: Fraction of data to use for testing
            random_state: Random seed for reproducibility

        Returns:
            Dictionary containing training metrics
        """
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_proba = self.model.predict_proba(X_test_scaled)[:, 1]

        # Calculate metrics
        self.metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'auc_roc': roc_auc_score(y_test, y_proba)
        }

        # Cross-validation score
        cv_scores = cross_val_score(
            self.model, X_train_scaled, y_train, cv=5, scoring='f1'
        )
        self.metrics['cv_f1_mean'] = cv_scores.mean()
        self.metrics['cv_f1_std'] = cv_scores.std()

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        self.metrics['confusion_matrix'] = cm.tolist()

        # Classification report
        self.metrics['classification_report'] = classification_report(
            y_test, y_pred, target_names=['Legitimate', 'Phishing']
        )

        # Set version
        self.model_version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.feature_names = FeatureExtractor.get_feature_names()

        return {
            'metrics': self.metrics,
            'version': self.model_version,
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'phishing_samples': int(y.sum()),
            'legitimate_samples': int(len(y) - y.sum())
        }

    def predict(self, url: str) -> Tuple[bool, float]:
        """
        Predict if a URL is phishing.

        Args:
            url: URL to check

        Returns:
            Tuple of (is_phishing, probability)
        """
        if self.model is None:
            raise ValueError("Model not loaded. Call load() or train() first.")

        features = self.feature_extractor.extract(url)
        feature_vector = np.array([self.feature_extractor.to_feature_vector(features)])

        if self.scaler:
            feature_vector = self.scaler.transform(feature_vector)

        proba = self.model.predict_proba(feature_vector)[0][1]
        prediction = proba >= 0.5

        return bool(prediction), float(proba)

    def predict_with_features(self, url: str) -> Tuple[bool, float, URLFeatures]:
        """
        Predict with feature details.

        Args:
            url: URL to check

        Returns:
            Tuple of (is_phishing, probability, features)
        """
        if self.model is None:
            raise ValueError("Model not loaded. Call load() or train() first.")

        features = self.feature_extractor.extract(url)
        feature_vector = np.array([self.feature_extractor.to_feature_vector(features)])

        if self.scaler:
            feature_vector = self.scaler.transform(feature_vector)

        proba = self.model.predict_proba(feature_vector)[0][1]
        prediction = proba >= 0.5

        return bool(prediction), float(proba), features

    def predict_batch(self, urls: List[str]) -> List[Tuple[bool, float]]:
        """
        Predict multiple URLs.

        Args:
            urls: List of URLs to check

        Returns:
            List of (is_phishing, probability) tuples
        """
        if self.model is None:
            raise ValueError("Model not loaded. Call load() or train() first.")

        feature_vectors = []
        for url in urls:
            features = self.feature_extractor.extract(url)
            feature_vectors.append(self.feature_extractor.to_feature_vector(features))

        X = np.array(feature_vectors)
        if self.scaler:
            X = self.scaler.transform(X)

        probas = self.model.predict_proba(X)[:, 1]
        predictions = probas >= 0.5

        return [(bool(pred), float(prob)) for pred, prob in zip(predictions, probas)]

    def get_feature_importance(self, top_n: int = 20) -> List[Tuple[str, float]]:
        """Get top N most important features."""
        if self.model is None or not self.feature_names:
            return []

        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1][:top_n]

        return [
            (self.feature_names[i], float(importances[i]))
            for i in indices
        ]

    def save(self, path: Path) -> None:
        """Save model to disk."""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'version': self.model_version,
            'metrics': self.metrics
        }
        joblib.dump(model_data, path)

    def load(self, path: Path) -> None:
        """Load model from disk."""
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.scaler = model_data.get('scaler')
        self.feature_names = model_data.get('feature_names', [])
        self.model_version = model_data.get('version', 'unknown')
        self.metrics = model_data.get('metrics', {})
