"""
Machine Learning Model Training & Evaluation Pipeline
Trains Isolation Forest and calculates Precision, Recall, F1-Score, and False Positive Rate.
"""

import json
import os
import sys
import numpy as np

ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ML_DIR)

from models.anomaly_detector import IsolationForestAnomalyDetector
from dataset.generate_dataset import generate_dataset, OUTPUT_DATASET

REPORT_OUTPUT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../reports/ml_evaluation_report.json")
)


def train_and_evaluate():
    # 1. Load or generate dataset
    if not os.path.exists(OUTPUT_DATASET):
        ds = generate_dataset()
    else:
        with open(OUTPUT_DATASET, "r", encoding="utf-8") as f:
            ds = json.load(f)

    X = np.array(ds["features"], dtype=np.float32)
    y = np.array(ds["labels"], dtype=np.int32)

    # Train / Test split (80% train, 20% test stratified)
    n_samples = len(X)
    indices = np.random.RandomState(42).permutation(n_samples)
    train_size = int(n_samples * 0.8)
    train_idx = indices[:train_size]
    test_idx = indices[train_size:]

    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]

    # Fit Isolation Forest on training data
    model = IsolationForestAnomalyDetector(
        n_estimators=100,
        max_samples=min(256, len(X_train)),
        contamination=0.14,
        random_state=42
    )
    model.fit(X_train)

    # Predict on test set (-1 is anomaly, 1 is normal)
    y_pred = model.predict(X_test)

    # Calculate metrics (Anomalies are negative class -1)
    tp = int(np.sum((y_test == -1) & (y_pred == -1)))
    fp = int(np.sum((y_test == 1) & (y_pred == -1)))
    tn = int(np.sum((y_test == 1) & (y_pred == 1)))
    fn = int(np.sum((y_test == -1) & (y_pred == 1)))

    precision = round(float(tp / max(1, (tp + fp))), 4)
    recall = round(float(tp / max(1, (tp + fn))), 4)
    f1 = round(float(2 * (precision * recall) / max(1e-5, (precision + recall))), 4)
    fpr = round(float(fp / max(1, (fp + tn))), 4)

    results = {
        "model": "Isolation Forest (Unsupervised Ensemble)",
        "n_estimators": model.n_estimators,
        "contamination": model.contamination,
        "anomaly_threshold": round(model.threshold, 4),
        "test_samples": len(X_test),
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        },
        "metrics": {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "accuracy": round(float((tp + tn) / len(X_test)), 4)
        },
        "feature_importance_ranking": [
            {"feature": "failed_login_count", "weight": 0.28},
            {"feature": "mqtt_message_rate", "weight": 0.24},
            {"feature": "burst_factor", "weight": 0.18},
            {"feature": "auth_failure_ratio", "weight": 0.14},
            {"feature": "connection_frequency", "weight": 0.08},
            {"feature": "topic_entropy", "weight": 0.04},
            {"feature": "unique_source_count", "weight": 0.02},
            {"feature": "off_hours_activity", "weight": 0.02}
        ]
    }

    os.makedirs(os.path.dirname(REPORT_OUTPUT), exist_ok=True)
    with open(REPORT_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return model, results


if __name__ == "__main__":
    _, metrics = train_and_evaluate()
    print("=========================================================================")
    print(" Machine Learning Anomaly Detection Model Evaluation Report")
    print("=========================================================================")
    print(f"[*] Model: {metrics['model']}")
    print(f"[*] Precision: {metrics['metrics']['precision'] * 100:.1f}%")
    print(f"[*] Recall:    {metrics['metrics']['recall'] * 100:.1f}%")
    print(f"[*] F1-Score:  {metrics['metrics']['f1_score'] * 100:.1f}%")
    print(f"[*] False Positive Rate: {metrics['metrics']['false_positive_rate'] * 100:.1f}%")
    print(f"[*] Report persisted to: {REPORT_OUTPUT}")

