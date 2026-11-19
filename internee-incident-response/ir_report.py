import os
import json
from collections import Counter

BASE_DIR = os.path.expanduser("~/internee-incident-response")
LOG_FILE = os.path.join(BASE_DIR, "logs/incident_response.jsonl")
SUMMARY_OUT = os.path.join(BASE_DIR, "submission_summary.txt")

def main():
    events = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            events = [json.loads(line) for line in f if line.strip()]

    phases = Counter(e.get("phase", "UNKNOWN") for e in events)
    summary = "\n".join([
        "Internee.pk Incident Response Task - Summary",
        f"Total IR & Drill Log Entries: {len(events)}",
        f"Phases Logged: {dict(phases)}",
        "Controls Configured: Pre-Incident Backup Snapshot, MITRE ATT&CK Ransomware Simulation, Containment/Mitigation, SHA-256 Recovery Verification, Staff Emergency Playbook."
    ]) + "\n"

    with open(SUMMARY_OUT, "w") as out:
        out.write(summary)

    print(summary)
    print(f"[+] Saved summary to: {SUMMARY_OUT}")

if __name__ == "__main__":
    main()
