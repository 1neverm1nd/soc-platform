"""Train SOC ML model: TF-IDF + VotingClassifier (LinearSVC + LogisticRegression)."""
import os, sys, json, pickle, csv
from datetime import datetime

import numpy as np
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import VotingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(SCRIPT_DIR, "training_data.csv")
MODEL_PATH = os.path.join(SCRIPT_DIR, "model.pkl")
META_PATH = os.path.join(SCRIPT_DIR, "model_metadata.json")
CM_PATH = os.path.join(SCRIPT_DIR, "confusion_matrix.json")


def load_data(path):
    texts, labels = [], []
    with open(path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("text") and row.get("label"):
                texts.append(row["text"])
                labels.append(row["label"])
    return texts, labels


def build_pipeline():
    word_tfidf = TfidfVectorizer(
        analyzer="word", ngram_range=(1, 3), max_features=8000,
        sublinear_tf=True, min_df=2
    )
    char_tfidf = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5), max_features=4000,
        sublinear_tf=True, min_df=2
    )
    features = FeatureUnion([("word", word_tfidf), ("char", char_tfidf)])

    svc = CalibratedClassifierCV(LinearSVC(C=0.8, max_iter=2000), cv=3, method="sigmoid")
    lr = LogisticRegression(C=2.0, solver="saga", max_iter=1000, n_jobs=-1)
    clf = VotingClassifier(estimators=[("svc", svc), ("lr", lr)], voting="soft", weights=[2, 1])

    return Pipeline([("features", features), ("clf", clf)])


def train(labeled_data_path=None):
    data_path = labeled_data_path or DATA_PATH

    if not os.path.exists(data_path):
        print(f"Training data not found at {data_path}")
        print("Run: python generate_training_data.py")
        sys.exit(1)

    print(f"Loading data from {data_path}...")
    texts, labels = load_data(data_path)
    print(f"  Loaded {len(texts)} samples, {len(set(labels))} classes")

    classes = sorted(set(labels))
    print(f"  Classes: {classes}")

    pipeline = build_pipeline()

    print("Running 5-fold cross-validation...")
    cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="accuracy", n_jobs=-1)
    print(f"  CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
    print("Training final model on full train set...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    test_acc = accuracy_score(y_test, y_pred)
    print(f"  Test Accuracy: {test_acc:.4f}")
    print(classification_report(y_test, y_pred, zero_division=0))

    print(f"Saving model to {MODEL_PATH}...")
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)

    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()
    with open(CM_PATH, "w") as f:
        json.dump({"matrix": cm, "labels": classes, "updatedAt": datetime.now().isoformat()}, f)

    metadata = {
        "accuracy": round(test_acc, 4),
        "cv_accuracy": round(float(cv_scores.mean()), 4),
        "cv_std": round(float(cv_scores.std()), 4),
        "model_type": "VotingClassifier(LinearSVC+LogisticRegression)",
        "training_samples": len(texts),
        "classes": classes,
        "trained_at": datetime.now().isoformat(),
        "features": "TF-IDF word(1-3) 8k + char_wb(3-5) 4k = 12k features",
    }
    with open(META_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[OK] Model saved. Accuracy: {test_acc:.1%}, CV: {cv_scores.mean():.1%}")
    return metadata


if __name__ == "__main__":
    labeled = sys.argv[1] if len(sys.argv) > 1 else None
    train(labeled)
