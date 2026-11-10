"""
Feature Extraction Pipeline for Security Anomaly Detection
Converts raw event sequences from Honeypots and IoT simulators into numerical feature vectors.
"""

from collections import Counter
import datetime
import math
from typing import Any, Dict, List
import numpy as np


class FeatureExtractor:
    FEATURE_NAMES = [
        "failed_login_count",
        "connection_frequency",
        "unique_source_count",
        "mqtt_message_rate",
        "auth_failure_ratio",
        "topic_entropy",
        "off_hours_activity",
        "burst_factor"
    ]

    @classmethod
    def extract_window_features(cls, events: List[Dict[str, Any]], window_seconds: float = 60.0) -> np.ndarray:
        """
        Extracts an 8-dimensional feature vector from a temporal window of events.
        """
        if not events:
            return np.zeros(len(cls.FEATURE_NAMES), dtype=np.float32)

        failed_logins = 0
        total_connections = 0
        mqtt_messages = 0
        source_ips = set()
        topics = []
        timestamps = []
        off_hours_count = 0

        for e in events:
            ev_type = e.get("event_type", "")
            src_ip = e.get("source_ip")
            if src_ip:
                source_ips.add(src_ip)

            if "login.failed" in ev_type or ev_type == "login_failed":
                failed_logins += 1
            if "connect" in ev_type:
                total_connections += 1
            if "mqtt" in ev_type or "topic" in e:
                mqtt_messages += 1
                topic = e.get("topic") or e.get("metadata", {}).get("topic")
                if topic:
                    topics.append(topic)

            ts_str = e.get("timestamp")
            if ts_str:
                try:
                    ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamps.append(ts.timestamp())
                    if ts.hour < 6 or ts.hour > 22:
                        off_hours_count += 1
                except Exception:
                    pass

        # 1. Failed login count
        feat_failed_logins = float(failed_logins)

        # 2. Connection frequency per minute
        feat_conn_freq = float(len(events)) / max(1.0, (window_seconds / 60.0))

        # 3. Unique source IPs count
        feat_unique_sources = float(len(source_ips))

        # 4. MQTT message rate
        feat_mqtt_rate = float(mqtt_messages) / max(1.0, (window_seconds / 10.0))

        # 5. Auth failure ratio
        feat_auth_ratio = float(failed_logins) / max(1.0, float(total_connections + failed_logins))

        # 6. Topic entropy
        if topics:
            counts = Counter(topics)
            total_t = len(topics)
            entropy = -sum((cnt / total_t) * math.log2(cnt / total_t) for cnt in counts.values())
        else:
            entropy = 0.0
        feat_topic_entropy = float(entropy)

        # 7. Off hours activity ratio
        feat_off_hours = float(off_hours_count) / max(1.0, float(len(events)))

        # 8. Burst factor (variance in event timing)
        if len(timestamps) >= 3:
            intervals = np.diff(np.sort(timestamps))
            burst_factor = float(np.std(intervals) / (np.mean(intervals) + 1e-5))
        else:
            burst_factor = 0.0

        return np.array([
            feat_failed_logins,
            feat_conn_freq,
            feat_unique_sources,
            feat_mqtt_rate,
            feat_auth_ratio,
            feat_topic_entropy,
            feat_off_hours,
            burst_factor
        ], dtype=np.float32)

