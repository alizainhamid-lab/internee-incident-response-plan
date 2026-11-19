import os
import json
import shutil
import hashlib
from datetime import datetime, timezone

BASE_DIR = os.path.expanduser("~/internee-incident-response")
TARGET_DIR = os.path.join(BASE_DIR, "lab_target_files")
VAULT_DIR = os.path.join(BASE_DIR, "recovery_vault")
LOG_FILE = os.path.join(BASE_DIR, "logs/incident_response.jsonl")

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def log_step(phase: str, technique: str, action: str, status: str, detail: str):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "mitre_attack": technique,
        "action": action,
        "status": status,
        "detail": detail
    }
    with open(LOG_FILE, "a") as lf:
        lf.write(json.dumps(entry) + "\n")
    print(f"[{phase} | {technique}] {action} -> {status}: {detail}")

def main():
    os.makedirs(VAULT_DIR, exist_ok=True)
    baselines = {}

    # 1. Pre-incident clean backup snapshot
    for fname in sorted(os.listdir(TARGET_DIR)):
        src = os.path.join(TARGET_DIR, fname)
        if os.path.isfile(src) and not fname.endswith(".locked"):
            baselines[fname] = sha256_file(src)
            shutil.copy2(src, os.path.join(VAULT_DIR, fname))

    log_step("PREPARATION", "T1531", "Create immutable clean backup snapshot", "COMPLETED", f"{len(baselines)} files backed up")

    # 2. Detection & Ransomware Simulation (safe non-destructive marker)
    log_step("DETECTION", "T1059.001", "Detect suspicious script burst & mass file rename pattern", "ALERT_HIGH", "Anomalous rapid write/extension change detected")
    log_step("DETECTION", "T1490", "Detect attempt to tamper with recovery/backup state", "ALERT_CRITICAL", "Recovery tampering behavior flagged by EDR rule")

    locked_count = 0
    for fname, orig_hash in baselines.items():
        orig_path = os.path.join(TARGET_DIR, fname)
        locked_path = os.path.join(TARGET_DIR, fname + ".locked")
        if os.path.exists(orig_path):
            with open(orig_path, "rb") as rf:
                data = rf.read()
            digest = hashlib.sha256(data).hexdigest()
            with open(locked_path, "w") as wf:
                wf.write(f"[SIMULATED_RANSOMWARE_LOCK_SHA256={digest}]\n")
            os.remove(orig_path)
            locked_count += 1

    log_step("CONTAINMENT_MITIGATION", "T1486", "Isolate affected host, revoke active tokens & block C2 IOCs", "MITIGATED", f"Simulated impact on {locked_count} files contained")

    # 3. Recovery & Post-Incident Verification
    restored = 0
    for fname, expected_hash in baselines.items():
        locked_path = os.path.join(TARGET_DIR, fname + ".locked")
        backup_path = os.path.join(VAULT_DIR, fname)
        restored_path = os.path.join(TARGET_DIR, fname)

        if os.path.exists(locked_path):
            os.remove(locked_path)
        shutil.copy2(backup_path, restored_path)
        actual_hash = sha256_file(restored_path)
        assert actual_hash == expected_hash, f"Hash mismatch on {fname}"
        restored += 1

    log_step("RECOVERY", "T1486", "Restore clean files from recovery vault & verify SHA-256", "VERIFIED", f"{restored}/{len(baselines)} files restored cleanly")

if __name__ == "__main__":
    main()
