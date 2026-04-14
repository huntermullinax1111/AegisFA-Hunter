import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

ALERTS_FILE = r"C:\AegisFA\alerts\alerts.json"
SUMMARY_FILE = r"C:\AegisFA\parsed\summary.json"

def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AegisFA - Security Operations Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', sans-serif; background: #0a0e1a; color: #e0e6f0; min-height: 100vh; }
  header { background: #0d1b2a; border-bottom: 1px solid #1e3a5f; padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 22px; color: #4fc3f7; letter-spacing: 2px; }
  header span { font-size: 12px; color: #546e7a; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 24px 32px 0; }
  .card { background: #0d1b2a; border: 1px solid #1e3a5f; border-radius: 10px; padding: 20px; }
  .card.critical { border-left: 4px solid #ef5350; }
  .card.high { border-left: 4px solid #ff9800; }
  .card.medium { border-left: 4px solid #ffeb3b; }
  .card.info { border-left: 4px solid #4fc3f7; }
  .card h3 { font-size: 12px; color: #546e7a; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .card .number { font-size: 36px; font-weight: 700; }
  .card.critical .number { color: #ef5350; }
  .card.high .number { color: #ff9800; }
  .card.medium .number { color: #ffeb3b; }
  .card.info .number { color: #4fc3f7; }
  .section { margin: 24px 32px; }
  .section h2 { font-size: 14px; color: #546e7a; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; border-bottom: 1px solid #1e3a5f; padding-bottom: 8px; }
  .alert-row { background: #0d1b2a; border: 1px solid #1e3a5f; border-radius: 8px; padding: 16px; margin-bottom: 10px; display: grid; grid-template-columns: 100px 1fr auto; gap: 16px; align-items: center; }
  .badge { padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; text-align: center; }
  .badge.critical { background: #3b1a1a; color: #ef5350; }
  .badge.high { background: #2d1f0a; color: #ff9800; }
  .badge.medium { background: #2d2a0a; color: #ffeb3b; }
  .alert-title { font-size: 14px; color: #e0e6f0; margin-bottom: 4px; }
  .alert-meta { font-size: 12px; color: #546e7a; }
  .mitre { font-size: 11px; color: #4fc3f7; background: #0a1929; padding: 3px 8px; border-radius: 4px; white-space: nowrap; }
  .log-row { background: #0d1b2a; border: 1px solid #1e3a5f; border-radius: 6px; padding: 10px 16px; margin-bottom: 6px; font-family: monospace; font-size: 12px; color: #78909c; }
  .log-row span { color: #4fc3f7; margin-right: 8px; }
  .footer { text-align: center; padding: 24px; color: #1e3a5f; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>AEGISFA // SECURITY OPERATIONS</h1>
  <span id="time"></span>
</header>

<div class="grid">
  <div class="card critical"><h3>Critical Alerts</h3><div class="number" id="critical">-</div></div>
  <div class="card high"><h3>High Alerts</h3><div class="number" id="high">-</div></div>
  <div class="card medium"><h3>Medium Alerts</h3><div class="number" id="medium">-</div></div>
  <div class="card info"><h3>Total Events</h3><div class="number" id="total">-</div></div>
</div>

<div class="section">
  <h2>Active Alerts</h2>
  <div id="alerts"></div>
</div>

<div class="section">
  <h2>Recent Log Events</h2>
  <div id="logs"></div>
</div>

<div class="footer">AegisFA &copy; 2026 &mdash; Hunter Mullinax &mdash; Lander University CIS-499</div>

<script>
document.getElementById('time').textContent = new Date().toLocaleString();

fetch('/data').then(r => r.json()).then(data => {
  const alerts = data.alerts || {};
  const summary = data.summary || {};

  document.getElementById('critical').textContent = alerts.critical ?? 0;
  document.getElementById('high').textContent = alerts.high ?? 0;
  document.getElementById('medium').textContent = alerts.medium ?? 0;
  document.getElementById('total').textContent = summary.total_events ?? 0;

  const alertDiv = document.getElementById('alerts');
  (alerts.alerts || []).forEach(a => {
    alertDiv.innerHTML += `
      <div class="alert-row">
        <span class="badge ${a.severity}">${a.severity}</span>
        <div>
          <div class="alert-title">${a.title}</div>
          <div class="alert-meta">${a.alert_id} &mdash; ${a.event_count} events &mdash; Hosts: ${a.affected_hosts.join(', ')}</div>
        </div>
        <span class="mitre">${a.mitre_technique}</span>
      </div>`;
  });

  const logDiv = document.getElementById('logs');
  const events = (summary.all_events || []).slice(0, 10);
  events.forEach(e => {
    logDiv.innerHTML += `
      <div class="log-row">
        <span>${e.timestamp}</span>${e.host} &mdash; [${e.category}] ${e.message.substring(0, 120)}
      </div>`;
  });
});
</script>
</body>
</html>
"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(HTML.encode())
        elif self.path == "/data":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            data = {
                "alerts": load_json(ALERTS_FILE),
                "summary": load_json(SUMMARY_FILE)
            }
            self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass

print("AegisFA Dashboard starting...")
print("Open your browser and go to: http://localhost:8080")
print("Press Ctrl+C to stop\n")
HTTPServer(("", 8080), Handler).serve_forever()