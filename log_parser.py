import re
import json
import os
from datetime import datetime


LOG_FILE = r"C:\AegisFA\logs\syslog.log"

OUTPUT_DIR = r"C:\AegisFA\parsed"
os.makedirs(OUTPUT_DIR, exist_ok=True)

#log typese
auth_events = []
firewall_events = []
system_events = []
credential_events = []
unknown_events = []

def parse_line(line):
    """Parse a single log line into a structured dictionary"""
    line = line.strip()
    if not line:
        return None

    
    pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+(.*)"
    match = re.match(pattern, line)
    
    if match:
        return {
            "timestamp": match.group(1),
            "host": match.group(2),
            "source": match.group(3).rstrip(":"),
            "message": match.group(4).strip(),
            "parsed_at": datetime.now().isoformat()
        }
    return {
        "timestamp": "unknown",
        "host": "unknown", 
        "source": "unknown",
        "message": line,
        "parsed_at": datetime.now().isoformat()
    }

def categorize(event):
    """Sort events into categories based on content"""
    if event is None:
        return
    
    msg = event["message"].lower()
    src = event["source"].lower()

    if "credential" in msg or "5379" in msg:
        event["category"] = "credential_access"
        event["severity"] = "medium"
        credential_events.append(event)

    elif "failed password" in msg or "failed login" in msg or "unauthorized" in msg:
        event["category"] = "authentication_failure"
        event["severity"] = "high"
        auth_events.append(event)

    elif "firewall" in src or "blocked" in msg or "dropped" in msg:
        event["category"] = "firewall_event"
        event["severity"] = "medium"
        firewall_events.append(event)

    elif "threat" in msg or "malware" in msg or "virus" in msg or "quarantine" in msg:
        event["category"] = "threat_detected"
        event["severity"] = "critical"
        system_events.append(event)

    elif "winevent" in src.lower() or "windows" in event["host"].lower():
        event["category"] = "windows_system"
        event["severity"] = "low"
        system_events.append(event)

    else:
        event["category"] = "unknown"
        event["severity"] = "low"
        unknown_events.append(event)

def save(name, events):
    """Save a category of events to its own JSON file"""
    path = os.path.join(OUTPUT_DIR, f"{name}.json")
    with open(path, "w") as f:
        json.dump(events, f, indent=2)
    print(f"  Saved {len(events)} events to {name}.json")

print("AegisFA Log Parser starting...")
print(f"Reading from: {LOG_FILE}")

if not os.path.exists(LOG_FILE):
    print("ERROR: Log file not found. Make sure your collector is running.")
    exit(1)

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

print(f"Found {len(lines)} log entries. Parsing...")

for line in lines:
    event = parse_line(line)
    categorize(event)

print("\nResults:")
save("auth_events", auth_events)
save("firewall_events", firewall_events)
save("credential_events", credential_events)
save("system_events", system_events)
save("unknown_events", unknown_events)

#summary
summary = {
    "parsed_at": datetime.now().isoformat(),
    "total_events": len(lines),
    "breakdown": {
        "authentication_failures": len(auth_events),
        "firewall_events": len(firewall_events),
        "credential_access": len(credential_events),
        "system_events": len(system_events),
        "unknown": len(unknown_events)
    },
    "all_events": auth_events + firewall_events + credential_events + system_events + unknown_events
}

summary_path = os.path.join(OUTPUT_DIR, "summary.json")
with open(summary_path, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\nSummary saved to summary.json")
print(f"Total events parsed: {summary['total_events']}")
print(f"Authentication failures: {len(auth_events)}")
print(f"Firewall events: {len(firewall_events)}")
print(f"Credential access: {len(credential_events)}")
print(f"System events: {len(system_events)}")
print("Done.")