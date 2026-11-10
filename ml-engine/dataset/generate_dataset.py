"""
Dataset Generator for Security Anomaly Detection
Generates labeled training and validation datasets combining baseline normal telemetry
and controlled cyberattack scenarios.
"""

import json
import os
import random
from typing import Any, Dict, List
import numpy as np

OUTPUT_DATASET = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "telemetry_dataset.json")
)


def generate_dataset(n_normal: int = 500, n_anomaly: int = 80) -> Dict[str, Any]:
    random.seed(42)
    np.random.seed(42)

    X_list: List[List[float]] = []
    y_list: List[int] = []  # 1 for normal, -1 for anomaly

    # 1. Normal Operational Telemetry
    # Features: [failed_logins, conn_freq, unique_sources, mqtt_rate, auth_ratio, topic_entropy, off_hours, burst_factor]
    for _ in range(n_normal):
        failed_logins = float(random.choice([0, 0, 0, 1]))
        conn_freq = float(random.uniform(5.0, 15.0))
        unique_sources = float(random.randint(1, 3))
        mqtt_rate = float(random.uniform(8.0, 12.0))
        auth_ratio = float(failed_logins / (conn_freq + 1.0))
        topic_entropy = float(random.uniform(1.8, 2.5))
        off_hours = float(random.choice([0.0, 0.0, 0.1]))
        burst_factor = float(random.uniform(0.1, 0.4))

        X_list.append([
            failed_logins, conn_freq, unique_sources, mqtt_rate,
            auth_ratio, topic_entropy, off_hours, burst_factor
        ])
        y_list.append(1)

    # 2. Attack Scenario A: SSH Brute-Force Spray
    for _ in range(n_anomaly // 3):
        failed_logins = float(random.randint(8, 30))
        conn_freq = float(random.uniform(25.0, 60.0))
        unique_sources = float(random.randint(1, 2))
        mqtt_rate = float(random.uniform(5.0, 10.0))
        auth_ratio = float(random.uniform(0.85, 0.99))
        topic_entropy = float(random.uniform(1.0, 1.8))
        off_hours = float(random.choice([0.2, 0.8]))
        burst_factor = float(random.uniform(0.8, 2.2))

        X_list.append([
            failed_logins, conn_freq, unique_sources, mqtt_rate,
            auth_ratio, topic_entropy, off_hours, burst_factor
        ])
        y_list.append(-1)

    # 3. Attack Scenario B: IoT Camera Botnet DDoS Flood
    for _ in range(n_anomaly // 3):
        failed_logins = 0.0
        conn_freq = float(random.uniform(40.0, 120.0))
        unique_sources = float(random.randint(1, 3))
        mqtt_rate = float(random.uniform(50.0, 150.0)) # Extreme rate
        auth_ratio = 0.0
        topic_entropy = float(random.uniform(0.1, 0.5)) # Low entropy: repeating target topic
        off_hours = float(random.choice([0.0, 0.5]))
        burst_factor = float(random.uniform(1.2, 3.5))

        X_list.append([
            failed_logins, conn_freq, unique_sources, mqtt_rate,
            auth_ratio, topic_entropy, off_hours, burst_factor
        ])
        y_list.append(-1)

    # 4. Attack Scenario C: Multi-Protocol Scanner
    for _ in range(n_anomaly - (2 * (n_anomaly // 3))):
        failed_logins = float(random.randint(2, 6))
        conn_freq = float(random.uniform(30.0, 70.0))
        unique_sources = float(random.randint(4, 10))
        mqtt_rate = float(random.uniform(1.0, 5.0))
        auth_ratio = float(random.uniform(0.4, 0.7))
        topic_entropy = float(random.uniform(2.8, 3.8)) # High scanning entropy
        off_hours = 0.6
        burst_factor = float(random.uniform(0.9, 2.0))

        X_list.append([
            failed_logins, conn_freq, unique_sources, mqtt_rate,
            auth_ratio, topic_entropy, off_hours, burst_factor
        ])
        y_list.append(-1)

    dataset = {
        "feature_names": [
            "failed_login_count", "connection_frequency", "unique_source_count",
            "mqtt_message_rate", "auth_failure_ratio", "topic_entropy",
            "off_hours_activity", "burst_factor"
        ],
        "n_samples": len(X_list),
        "n_normal": n_normal,
        "n_anomaly": n_anomaly,
        "features": X_list,
        "labels": y_list
    }

    os.makedirs(os.path.dirname(OUTPUT_DATASET), exist_ok=True)
    with open(OUTPUT_DATASET, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    return dataset


if __name__ == "__main__":
    ds = generate_dataset()
    print(f"[+] Successfully generated dataset with {ds['n_samples']} samples ({ds['n_normal']} normal, {ds['n_anomaly']} anomalies).")
    print(f"[+] Saved to: {OUTPUT_DATASET}")
