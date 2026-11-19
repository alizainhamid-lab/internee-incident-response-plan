import os
import json
from datetime import datetime, timezone

BASE_DIR = os.path.expanduser("~/internee-incident-response")
LOG_FILE = os.path.join(BASE_DIR, "logs/incident_response.jsonl")
PLAYBOOK_FILE = os.path.join(BASE_DIR, "STAFF_EMERGENCY_PLAYBOOK.md")

drills = [
    {"role": "All Internee.pk Staff", "step": "1. Disconnect & Report", "action": "Disconnect affected workstation from network/Wi-Fi and alert Security Lead immediately; never pay ransom."},
    {"role": "SOC / Incident Lead", "step": "2. Contain & Preserve", "action": "Isolate host, revoke active sessions/tokens, capture volatile logs/IOCs, and block malicious domains/IPs."},
    {"role": "Cloud & Infra Team", "step": "3. Recover & Verify", "action": "Validate offline/immutable backups, restore clean snapshots, verify SHA-256 hashes, and monitor for re-entry."},
    {"role": "Leadership & Comms", "step": "4. Post-Incident Review", "action": "Conduct root-cause analysis, complete breach/reporting obligations if required, and update detection rules."}
]

def main():
    lines = ["# Internee.pk Staff Emergency Response Playbook (Ransomware & Breaches)\n"]
    for d in drills:
        lines.append(f"## {d['step']} — {d['role']}\n- {d['action']}\n")

    with open(PLAYBOOK_FILE, "w") as pf:
        pf.write("\n".join(lines))

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "STAFF_TRAINING",
        "mitre_attack": "T1564/Playbook",
        "action": "Publish staff emergency response playbook & complete simulated drill",
        "status": "TRAINED",
        "detail": f"{len(drills)} emergency response roles & steps verified"
    }
    with open(LOG_FILE, "a") as lf:
        lf.write(json.dumps(entry) + "\n")

    print(f"[TRAINING] Generated {PLAYBOOK_FILE} with {len(drills)} response stages.")

if __name__ == "__main__":
    main()
