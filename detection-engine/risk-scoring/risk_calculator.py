"""
Explainable Multi-Factor Risk Scoring Engine
Calculates a deterministic 0-100 risk score and provides complete mathematical factor transparency.
"""

from typing import Any, Dict


class RiskScoreCalculator:
    # Severity base mappings (0-100 scale)
    BASE_SEVERITY_WEIGHTS = {
        "LOW": 20.0,
        "MEDIUM": 45.0,
        "HIGH": 75.0,
        "CRITICAL": 95.0
    }

    # Factor weights summing to 1.00
    WEIGHT_SEVERITY = 0.35
    WEIGHT_FREQUENCY = 0.20
    WEIGHT_THREAT_INTEL = 0.25
    WEIGHT_ML_ANOMALY = 0.20

    @classmethod
    def calculate_risk(
        cls,
        severity: str = "LOW",
        event_count: int = 1,
        threat_intel_score: float = 0.0,
        ml_anomaly_score: float = 0.0,
        asset_criticality: float = 1.0
    ) -> Dict[str, Any]:
        """
        Calculates explainable risk score (0-100).
        Formula:
          Score = min(100, (BaseSeverity * 0.35) + (FreqNorm * 0.20) + (TIScore * 0.25) + (MLAnomaly * 0.20)) * AssetMultiplier
        """
        base_sev = cls.BASE_SEVERITY_WEIGHTS.get(severity.upper(), 20.0)

        # Frequency normalization: 1 event = 10, 10+ events = 100
        freq_norm = min(100.0, (event_count / 10.0) * 100.0)

        # Threat Intel score clamp (0 to 100)
        ti_norm = max(0.0, min(100.0, float(threat_intel_score)))

        # ML Anomaly score clamp (0 to 100)
        ml_norm = max(0.0, min(100.0, float(ml_anomaly_score)))

        # Compute weighted contributions
        contrib_severity = round(base_sev * cls.WEIGHT_SEVERITY, 2)
        contrib_frequency = round(freq_norm * cls.WEIGHT_FREQUENCY, 2)
        contrib_threat_intel = round(ti_norm * cls.WEIGHT_THREAT_INTEL, 2)
        contrib_ml = round(ml_norm * cls.WEIGHT_ML_ANOMALY, 2)

        raw_score = contrib_severity + contrib_frequency + contrib_threat_intel + contrib_ml
        final_score = round(min(100.0, raw_score * asset_criticality), 1)

        # Determine qualitative severity level
        if final_score >= 75.0:
            tier = "CRITICAL"
        elif final_score >= 50.0:
            tier = "HIGH"
        elif final_score >= 30.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        return {
            "score": final_score,
            "tier": tier,
            "weights": {
                "severity_contribution": contrib_severity,
                "frequency_contribution": contrib_frequency,
                "threat_intel_contribution": contrib_threat_intel,
                "ml_anomaly_contribution": contrib_ml
            },
            "inputs": {
                "base_severity": base_sev,
                "event_count": event_count,
                "threat_intel_score": ti_norm,
                "ml_anomaly_score": ml_norm,
                "asset_criticality": asset_criticality
            },
            "formula": "Score = (BaseSeverity * 0.35) + (FrequencyNorm * 0.20) + (ThreatIntel * 0.25) + (MLAnomaly * 0.20)"
        }

