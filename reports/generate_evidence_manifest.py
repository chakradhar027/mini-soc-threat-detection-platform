#!/usr/bin/env python3
"""
Evidence Integrity Attestation Generator
Computes SHA-256 cryptographic hashes across all security event logs,
forensic incident evidence, audit chains, and reports.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "soar"))

from audit_logger import AuditLogger

MANIFEST_PATH = os.path.join(ROOT_DIR, "reports/evidence_integrity_manifest.json")


def hash_file_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "FILE_NOT_YET_CREATED"
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def generate_manifest():
    audit = AuditLogger()
    audit_chain_valid = audit.verify_integrity()

    artifacts_to_hash = [
        ("cowrie_logs", "infrastructure/docker/volumes/cowrie/log/cowrie.json"),
        ("dionaea_logs", "infrastructure/docker/volumes/dionaea/log/dionaea.json"),
        ("mosquitto_logs", "infrastructure/docker/volumes/mosquitto/log/mqtt_honey.json"),
        ("iot_telemetry", "infrastructure/docker/volumes/mosquitto/log/iot_telemetry.json"),
        ("incident_database", "reports/incidents.json"),
        ("soar_audit_chain", "reports/audit_trail.json"),
        ("ml_model_evaluation", "reports/ml_evaluation_report.json")
    ]

    hashes = {}
    for label, rel_path in artifacts_to_hash:
        full_p = os.path.join(ROOT_DIR, rel_path)
        hashes[label] = {
            "path": rel_path,
            "sha256": hash_file_sha256(full_p),
            "size_bytes": os.path.getsize(full_p) if os.path.exists(full_p) else 0,
            "last_modified": datetime.fromtimestamp(os.path.getmtime(full_p), timezone.utc).isoformat() if os.path.exists(full_p) else None
        }

    manifest = {
        "manifest_version": "1.0.0",
        "attestation_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "platform": "Mini SOC & Threat Detection Platform",
        "hashing_algorithm": "SHA-256",
        "audit_chain_verified": audit_chain_valid,
        "latest_audit_hash": audit.get_last_hash(),
        "total_audit_records": len(audit.get_all_entries()),
        "artifact_hashes": hashes
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("=========================================================================")
    print(" EVIDENCE INTEGRITY ATTESTATION MANIFEST GENERATED")
    print("=========================================================================")
    print(f"[*] Audit Hash Chain Status: {'VALID (UNBROKEN)' if audit_chain_valid else 'FAILED (TAMPERED)'}")
    print(f"[*] Total Cryptographic Audit Records: {manifest['total_audit_records']}")
    print(f"[*] Manifest Path: {MANIFEST_PATH}")
    print("-------------------------------------------------------------------------")
    for k, v in hashes.items():
        print(f"  - {k:<20}: {v['sha256'][:24]}... ({v['size_bytes']} bytes)")
    print("=========================================================================")

    return manifest


if __name__ == "__main__":
    generate_manifest()

