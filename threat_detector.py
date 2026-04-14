import json
import os
from datetime import datetime
from collections import defaultdict


PARSED_DIR = r"C:\AegisFA\parsed"
OUTPUT_DIR = r"C:\AegisFA\alerts"
os.makedirs(OUTPUT_DIR, exist_ok=True)

alerts = []

def load(filename):
    """Load a parsed JSON log file"""
    path = os.path.join(PARSED_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)

def alert(severity, title, description, events, mitre):
    """Create a structured alert"""
    a = {
        "alert_id": f"AEGISFA-{len(alerts)+1:04d}",
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "title": title,
        "description": description,
        "mitre_technique": mitre,
        "event_count": len(events),
        "source_ips": list(set([
            e.get("message", "").split("from ")[-1].split(" ")[0]
            for e in events
            if "from " in e.get("message", "")
        ])),
        "affected_hosts": list(set([e.get("host", "unknown") for e in events])),
        "raw_events": events
    }
    alerts.append(a)
    print(f"  [{severity.upper()}] {title}")
    print(f"    MITRE: {mitre}")
    print(f"    Events: {len(events)}")
    if a["source_ips"]:
        print(f"    Source IPs: {', '.join(a['source_ips'])}")
    print()

def check_brute_force(auth_events):
    """Detect brute force - multiple failures from same IP"""
    ip_counts = defaultdict(list)
    for event in auth_events:
        msg = event.get("message", "")
        if "from " in msg:
            ip = msg.split("from ")[-1].split(" ")[0]
            ip_counts[ip].append(event)
    
    for ip, events in ip_counts.items():
        if len(events) >= 3:
            alert(
                severity="critical",
                title=f"Brute Force Attack Detected from {ip}",
                description=f"{len(events)} failed login attempts from {ip} - possible brute force attack matching MITRE ATT&CK T1110",
                events=events,
                mitre="T1110 - Brute Force"
            )

def check_credential_access(credential_events):
    """Detect suspicious credential access patterns"""
    if len(credential_events) >= 5:
        alert(
            severity="high",
            title="Excessive Credential Manager Access",
            description=f"{len(credential_events)} credential read operations detected - possible credential dumping or harvesting activity",
            events=credential_events,
            mitre="T1555 - Credentials from Password Stores"
        )

def check_firewall_events(firewall_events):
    """Detect suspicious firewall blocks"""
    rdp_blocks = [e for e in firewall_events if "3389" in e.get("message", "")]
    if rdp_blocks:
        alert(
            severity="high",
            title="RDP Access Attempt Blocked",
            description=f"Firewall blocked {len(rdp_blocks)} RDP connection attempt(s) on port 3389 - possible remote access attack",
            events=rdp_blocks,
            mitre="T1021.001 - Remote Desktop Protocol"
        )

    other_blocks = [e for e in firewall_events if "3389" not in e.get("message", "")]
    if other_blocks:
        alert(
            severity="medium",
            title="Suspicious Outbound Traffic Blocked",
            description=f"Firewall blocked {len(other_blocks)} suspicious connection(s)",
            events=other_blocks,
            mitre="T1041 - Exfiltration Over C2 Channel"
        )

def check_malware(system_events):
    """Detect malware or threat detections"""
    threats = [e for e in system_events if "threat" in e.get("message", "").lower() or "quarantine" in e.get("message", "").lower()]
    if threats:
        alert(
            severity="critical",
            title="Malware Detected and Quarantined",
            description=f"{len(threats)} malware detection(s) found - immediate investigation recommended",
            events=threats,
            mitre="T1204 - User Execution"
        )


print("AegisFA Threat Detector starting...")
print("Analyzing parsed logs for attack patterns...\n")

auth_events = load("auth_events.json")
firewall_events = load("firewall_events.json")
credential_events = load("credential_events.json")
system_events = load("system_events.json")

print("Running detection rules:")
print("-" * 40)

check_brute_force(auth_events)
check_credential_access(credential_events)
check_firewall_events(firewall_events)
check_malware(system_events)

if not alerts:
    print("No threats detected.")
else:
    # save
    output = {
        "scan_time": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "critical": len([a for a in alerts if a["severity"] == "critical"]),
        "high": len([a for a in alerts if a["severity"] == "high"]),
        "medium": len([a for a in alerts if a["severity"] == "medium"]),
        "alerts": alerts
    }

    path = os.path.join(OUTPUT_DIR, "alerts.json")
    with open(path, "w") as f:
        json.dump(output, f, indent=2)

    print("-" * 40)
    print(f"Total alerts generated: {len(alerts)}")
    print(f"Critical: {output['critical']}")
    print(f"High:     {output['high']}")
    print(f"Medium:   {output['medium']}")
    print(f"\nAlerts saved to: {path}")

print("\nDone.")