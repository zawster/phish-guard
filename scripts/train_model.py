"""Script to train the phishing detection ML model."""
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

import pandas as pd
import numpy as np
from datetime import datetime

from config.settings import settings
from src.ml.feature_extractor import FeatureExtractor
from src.ml.model import PhishingModel
from src.database.models import init_db, get_session, PhishTankEntry, MLModel

# File paths
PHISHING_CSV = settings.BASE_DIR / "verified_online.csv"
LEGITIMATE_CSV = settings.BASE_DIR / "tranco_7N42X.csv"


def load_phishing_data(csv_path: Path) -> pd.DataFrame:
    """Load phishing URLs from PhishTank CSV."""
    print(f"Loading phishing data from {csv_path}...")
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} phishing URLs")
    return df


def load_legitimate_data(csv_path: Path, max_samples: int = 10000) -> list:
    """
    Load legitimate URLs from Tranco CSV.

    Tranco format: rank,domain (e.g., "1,google.com")
    We convert domains to full URLs with various path patterns.
    """
    print(f"\nLoading legitimate data from {csv_path}...")

    # Read Tranco CSV (no header)
    df = pd.read_csv(csv_path, header=None, names=['rank', 'domain'])

    # Take top domains up to max_samples
    domains = df['domain'].head(max_samples).tolist()
    print(f"Loaded {len(domains)} legitimate domains from Tranco")

    # Convert domains to full URLs with variations
    legitimate_urls = []

    # Common path patterns for legitimate sites
    path_variations = [
        "",  # Root
        "/",
        "/login",
        "/signin",
        "/account",
        "/home",
        "/about",
        "/contact",
        "/help",
        "/support",
        "/products",
        "/services",
        "/blog",
        "/news",
        "/search",
        "/profile",
        "/settings",
        "/dashboard",
    ]

    for domain in domains:
        # Add HTTPS URLs (most legitimate sites use HTTPS)
        legitimate_urls.append(f"https://{domain}")
        legitimate_urls.append(f"https://www.{domain}")

        # Add some path variations for diversity
        # Only add a few paths per domain to avoid explosion
        for path in path_variations[:5]:
            legitimate_urls.append(f"https://{domain}{path}")

    # Shuffle and limit
    np.random.seed(42)
    np.random.shuffle(legitimate_urls)

    print(f"Generated {len(legitimate_urls)} legitimate URL variations")
    return legitimate_urls


def prepare_training_data(
    phishing_df: pd.DataFrame,
    legitimate_urls: list,
    phishing_samples: int = 10000,
    legitimate_samples: int = 10000
):
    """
    Prepare balanced training dataset.

    Args:
        phishing_df: DataFrame with phishing URLs
        legitimate_urls: List of legitimate URLs
        phishing_samples: Number of phishing samples to use
        legitimate_samples: Number of legitimate samples to use
    """
    print("\n" + "=" * 60)
    print("PREPARING TRAINING DATA")
    print("=" * 60)

    feature_extractor = FeatureExtractor()

    # Get phishing URLs
    phishing_urls = phishing_df['url'].dropna().unique().tolist()

    # Sample phishing URLs
    if len(phishing_urls) > phishing_samples:
        np.random.seed(42)
        phishing_urls = list(np.random.choice(phishing_urls, phishing_samples, replace=False))
    print(f"\nUsing {len(phishing_urls)} phishing URLs")

    # Sample legitimate URLs
    if len(legitimate_urls) > legitimate_samples:
        legitimate_urls = legitimate_urls[:legitimate_samples]
    print(f"Using {len(legitimate_urls)} legitimate URLs")

    # Calculate ratio
    total = len(phishing_urls) + len(legitimate_urls)
    phishing_ratio = len(phishing_urls) / total * 100
    legitimate_ratio = len(legitimate_urls) / total * 100
    print(f"\nClass distribution:")
    print(f"  Phishing:   {len(phishing_urls):,} ({phishing_ratio:.1f}%)")
    print(f"  Legitimate: {len(legitimate_urls):,} ({legitimate_ratio:.1f}%)")

    # Extract features
    print("\nExtracting features...")
    X = []
    y = []
    failed_urls = 0

    # Process phishing URLs
    print("\nProcessing phishing URLs...")
    for i, url in enumerate(phishing_urls):
        if i % 2000 == 0:
            print(f"  Progress: {i:,}/{len(phishing_urls):,} phishing URLs")
        try:
            features = feature_extractor.extract(url)
            feature_vector = feature_extractor.to_feature_vector(features)
            X.append(feature_vector)
            y.append(1)  # Phishing = 1
        except Exception as e:
            failed_urls += 1
            continue

    phishing_extracted = len([label for label in y if label == 1])
    print(f"  Extracted features from {phishing_extracted:,} phishing URLs")

    # Process legitimate URLs
    print("\nProcessing legitimate URLs...")
    for i, url in enumerate(legitimate_urls):
        if i % 2000 == 0:
            print(f"  Progress: {i:,}/{len(legitimate_urls):,} legitimate URLs")
        try:
            features = feature_extractor.extract(url)
            feature_vector = feature_extractor.to_feature_vector(features)
            X.append(feature_vector)
            y.append(0)  # Legitimate = 0
        except Exception as e:
            failed_urls += 1
            continue

    legitimate_extracted = len([label for label in y if label == 0])
    print(f"  Extracted features from {legitimate_extracted:,} legitimate URLs")

    X = np.array(X)
    y = np.array(y)

    print(f"\n" + "-" * 40)
    print(f"DATASET SUMMARY")
    print(f"-" * 40)
    print(f"  Total samples:      {len(y):,}")
    print(f"  Phishing samples:   {sum(y):,}")
    print(f"  Legitimate samples: {len(y) - sum(y):,}")
    print(f"  Failed extractions: {failed_urls:,}")
    print(f"  Feature dimensions: {X.shape[1]}")

    return X, y


def import_phishtank_to_db(phishing_df: pd.DataFrame, session):
    """Import PhishTank data to database."""
    import hashlib

    print("\nImporting PhishTank data to database...")

    count = session.query(PhishTankEntry).count()
    if count > 0:
        print(f"  Database already has {count:,} entries. Skipping import.")
        return

    entries = []
    for _, row in phishing_df.iterrows():
        url = row['url']
        url_hash = hashlib.sha256(url.encode()).hexdigest()

        entry = PhishTankEntry(
            phish_id=int(row['phish_id']),
            url=url,
            url_hash=url_hash,
            target=row.get('target', 'Other'),
            online=row.get('online', 'yes') == 'yes',
            synced_at=datetime.utcnow()
        )
        entries.append(entry)

    # Bulk insert in batches
    batch_size = 1000
    for i in range(0, len(entries), batch_size):
        batch = entries[i:i + batch_size]
        for entry in batch:
            try:
                session.add(entry)
            except Exception:
                continue
        session.commit()
        if (i + batch_size) % 10000 == 0:
            print(f"  Imported {min(i + batch_size, len(entries)):,}/{len(entries):,} entries")

    print(f"  Database now has {session.query(PhishTankEntry).count():,} PhishTank entries")


def save_model_metadata(session, model: PhishingModel, training_info: dict):
    """Save model metadata to database."""
    ml_model = MLModel(
        version=model.model_version,
        model_type="RandomForestClassifier",
        model_path=str(settings.MODEL_PATH),
        accuracy=training_info['metrics'].get('accuracy'),
        precision=training_info['metrics'].get('precision'),
        recall=training_info['metrics'].get('recall'),
        f1_score=training_info['metrics'].get('f1_score'),
        auc_roc=training_info['metrics'].get('auc_roc'),
        training_samples=training_info.get('training_samples'),
        phishing_samples=training_info.get('phishing_samples'),
        legitimate_samples=training_info.get('legitimate_samples'),
        is_active=True,
        hyperparameters={
            'n_estimators': 100,
            'max_depth': 20,
            'min_samples_split': 5,
            'min_samples_leaf': 2
        },
        feature_names=FeatureExtractor.get_feature_names()
    )

    # Deactivate previous models
    session.query(MLModel).update({'is_active': False})
    session.add(ml_model)
    session.commit()
    print(f"\nModel metadata saved. Version: {model.model_version}")


def main():
    """Main training function."""
    print("=" * 60)
    print("PHISHING DETECTION MODEL TRAINING")
    print("=" * 60)
    print(f"\nData sources:")
    print(f"  Phishing:   {PHISHING_CSV}")
    print(f"  Legitimate: {LEGITIMATE_CSV}")

    # Initialize database
    print("\nInitializing database...")
    engine = init_db(settings.DATABASE_URL)
    session = get_session(engine)

    # Load phishing data
    phishing_df = load_phishing_data(PHISHING_CSV)

    # Import to database (skip if already done)
    import_phishtank_to_db(phishing_df, session)

    # Load legitimate data from Tranco
    legitimate_urls = load_legitimate_data(LEGITIMATE_CSV, max_samples=5000)

    # Prepare training data with balanced classes
    # Using 10K phishing and 10K legitimate for balanced training
    X, y = prepare_training_data(
        phishing_df,
        legitimate_urls,
        phishing_samples=10000,
        legitimate_samples=10000
    )

    # Train model
    print("\n" + "=" * 60)
    print("TRAINING MODEL")
    print("=" * 60)

    model = PhishingModel()
    training_info = model.train(X, y)

    # Print results
    print("\n" + "=" * 60)
    print("TRAINING RESULTS")
    print("=" * 60)
    print(f"\nModel Version: {training_info['version']}")
    print(f"\nDataset:")
    print(f"  Training samples:   {training_info['training_samples']:,}")
    print(f"  Test samples:       {training_info['test_samples']:,}")
    print(f"  Phishing samples:   {training_info['phishing_samples']:,}")
    print(f"  Legitimate samples: {training_info['legitimate_samples']:,}")

    print(f"\nMetrics:")
    print(f"  Accuracy:  {training_info['metrics']['accuracy']:.4f}")
    print(f"  Precision: {training_info['metrics']['precision']:.4f}")
    print(f"  Recall:    {training_info['metrics']['recall']:.4f}")
    print(f"  F1 Score:  {training_info['metrics']['f1_score']:.4f}")
    print(f"  AUC-ROC:   {training_info['metrics']['auc_roc']:.4f}")
    print(f"  CV F1:     {training_info['metrics']['cv_f1_mean']:.4f} (+/- {training_info['metrics']['cv_f1_std']:.4f})")

    print(f"\nClassification Report:")
    print(training_info['metrics']['classification_report'])

    # Feature importance
    print("\nTop 15 Most Important Features:")
    for feature, importance in model.get_feature_importance(15):
        print(f"  {feature}: {importance:.4f}")

    # Save model
    print(f"\nSaving model to {settings.MODEL_PATH}...")
    settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    model.save(settings.MODEL_PATH)
    print("Model saved successfully!")

    # Save metadata to database
    save_model_metadata(session, model, training_info)

    # Test predictions
    print("\n" + "=" * 60)
    print("TEST PREDICTIONS")
    print("=" * 60)

    test_urls = [
        # Legitimate URLs
        ("https://www.google.com", "Legitimate"),
        ("https://www.paypal.com/signin", "Legitimate"),
        ("https://www.github.com/microsoft/vscode", "Legitimate"),
        ("https://www.amazon.com/dp/B08N5WRWNW", "Legitimate"),
        ("https://www.facebook.com/login", "Legitimate"),
        # Phishing URLs
        ("https://paypa1-verify.suspicious.tk/login", "Phishing"),
        ("https://secure-amazon.com.phishing.xyz/update", "Phishing"),
        ("https://192.168.1.1/admin/login.php", "Phishing"),
        ("https://facebook-login.suspicious.ml/verify", "Phishing"),
        ("https://g00gle-secure.tk/account/verify", "Phishing"),
    ]

    print(f"\n{'URL':<55} {'Expected':<12} {'Predicted':<12} {'Score':<8}")
    print("-" * 90)

    correct = 0
    for url, expected in test_urls:
        is_phishing, prob = model.predict(url)
        predicted = "Phishing" if is_phishing else "Legitimate"
        is_correct = predicted == expected
        correct += 1 if is_correct else 0
        mark = "[OK]" if is_correct else "[X]"
        print(f"{url[:53]:<55} {expected:<12} {predicted:<12} {prob:.2%} {mark}")

    print(f"\nTest accuracy: {correct}/{len(test_urls)} ({correct/len(test_urls)*100:.0f}%)")

    session.close()
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    main()
