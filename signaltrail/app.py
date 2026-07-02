from __future__ import annotations

import argparse
import json
import plistlib
import select
import socket
import socketserver
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from .ai import generate_ai_analysis
from .analyzer import analyze_events, classify_domain, format_bytes


class TrafficStore:
    def __init__(self, limit: int = 5000) -> None:
        self._events: list[dict[str, Any]] = []
        self._limit = limit
        self._lock = threading.Lock()

    def add(self, event: dict[str, Any]) -> None:
        event["id"] = str(uuid.uuid4())
        event["tags"] = classify_domain(str(event.get("host") or ""), str(event.get("path") or ""))
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._limit:
                del self._events[: len(self._events) - self._limit]

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


STORE = TrafficStore()


def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


class ProxyHandler(socketserver.StreamRequestHandler):
    timeout = 10

    def handle(self) -> None:
        started = time.time()
        request_line = self.rfile.readline(65536).decode("iso-8859-1", "replace").strip()
        if not request_line:
            return
        parts = request_line.split()
        if len(parts) != 3:
            return
        method, target, version = parts
        headers = self._read_headers()

        if method.upper() == "CONNECT":
            host, port = parse_connect_target(target)
            event = self._tunnel_https(host, port, target, started)
        else:
            event = self._forward_http(method, target, version, headers, started)

        if event:
            STORE.add(event)

    def _read_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        while True:
            line = self.rfile.readline(65536).decode("iso-8859-1", "replace")
            if line in ("\r\n", "\n", ""):
                break
            name, _, value = line.partition(":")
            if name:
                headers[name.strip().lower()] = value.strip()
        return headers

    def _tunnel_https(self, host: str, port: int, target: str, started: float) -> dict[str, Any]:
        client_to_server = 0
        server_to_client = 0
        status = "ok"
        try:
            upstream = socket.create_connection((host, port), timeout=10)
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client_to_server, server_to_client = bridge_sockets(self.connection, upstream)
        except OSError as exc:
            status = f"error: {exc}"
            try:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass
        return {
            "started_at": started,
            "duration_ms": int((time.time() - started) * 1000),
            "scheme": "https",
            "method": "CONNECT",
            "host": host,
            "port": port,
            "path": "",
            "target": target,
            "status": status,
            "bytes_client_to_server": client_to_server,
            "bytes_server_to_client": server_to_client,
            "client": self.client_address[0],
        }

    def _forward_http(
        self,
        method: str,
        target: str,
        version: str,
        headers: dict[str, str],
        started: float,
    ) -> dict[str, Any]:
        parsed = urlsplit(target)
        host_header = headers.get("host", "")
        host = parsed.hostname or host_header.split(":")[0]
        port = parsed.port or (80 if parsed.scheme in ("", "http") else 443)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        response_status = "unknown"
        client_to_server = 0
        server_to_client = 0

        try:
            upstream = socket.create_connection((host, port), timeout=10)
            with upstream:
                request = f"{method} {path} {version}\r\n"
                upstream.sendall(request.encode("iso-8859-1"))
                client_to_server += len(request)
                for name, value in headers.items():
                    if name == "proxy-connection":
                        continue
                    header_line = f"{canonical_header(name)}: {value}\r\n"
                    upstream.sendall(header_line.encode("iso-8859-1"))
                    client_to_server += len(header_line)
                upstream.sendall(b"Connection: close\r\n\r\n")
                client_to_server += len("Connection: close\r\n\r\n")

                while True:
                    chunk = upstream.recv(65536)
                    if not chunk:
                        break
                    if response_status == "unknown":
                        response_status = chunk.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
                    self.wfile.write(chunk)
                    server_to_client += len(chunk)
        except OSError as exc:
            response_status = f"error: {exc}"
            try:
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass

        return {
            "started_at": started,
            "duration_ms": int((time.time() - started) * 1000),
            "scheme": "http",
            "method": method,
            "host": host,
            "port": port,
            "path": path,
            "target": target,
            "status": response_status,
            "bytes_client_to_server": client_to_server,
            "bytes_server_to_client": server_to_client,
            "client": self.client_address[0],
        }


def parse_connect_target(target: str) -> tuple[str, int]:
    host, _, port_text = target.partition(":")
    return host, int(port_text or "443")


def canonical_header(name: str) -> str:
    return "-".join(part.capitalize() for part in name.split("-"))


def bridge_sockets(client: socket.socket, upstream: socket.socket) -> tuple[int, int]:
    sockets = [client, upstream]
    totals = {client: 0, upstream: 0}
    upstream.setblocking(False)
    client.setblocking(False)
    deadline = time.time() + 300
    try:
        while time.time() < deadline:
            readable, _, errored = select.select(sockets, [], sockets, 1)
            if errored:
                break
            if not readable:
                continue
            for source in readable:
                target = upstream if source is client else client
                try:
                    data = source.recv(65536)
                    if not data:
                        return totals[client], totals[upstream]
                    target.sendall(data)
                    totals[source] += len(data)
                except OSError:
                    return totals[client], totals[upstream]
    finally:
        upstream.close()
    return totals[client], totals[upstream]


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SignalTrail/0.1"

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self._send_html(dashboard_html(self.server.server_address[1]))
        elif parsed.path == "/events":
            self._send_json(STORE.snapshot()[-500:])
        elif parsed.path == "/report":
            self._send_json(analyze_events(STORE.snapshot()))
        elif parsed.path == "/audit":
            self._send_json(analyze_events(STORE.snapshot())["privacy_audit"])
        elif parsed.path == "/ai":
            self._send_json(generate_ai_analysis(analyze_events(STORE.snapshot())))
        elif parsed.path == "/export":
            report = analyze_events(STORE.snapshot())
            self._send_json({"events": STORE.snapshot(), "report": report, "ai": generate_ai_analysis(report)})
        elif parsed.path == "/profile.mobileconfig":
            query = parse_qs(parsed.query)
            proxy_host = query.get("host", [local_ip()])[0]
            proxy_port = int(query.get("port", ["9090"])[0])
            self._send_mobileconfig(proxy_host, proxy_port)
        elif parsed.path == "/qr.svg":
            query = parse_qs(parsed.query)
            data = query.get("data", [""])[0]
            self._send_html(qr_fallback_svg(data), content_type="image/svg+xml")
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if urlsplit(self.path).path == "/clear":
            STORE.clear()
            self._send_json({"ok": True})
        else:
            self.send_error(404)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send_json(self, payload: Any) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str, content_type: str = "text/html") -> None:
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_mobileconfig(self, proxy_host: str, proxy_port: int) -> None:
        payload_id = "dev.signaltrail.proxy"
        profile = {
            "PayloadContent": [
                {
                    "PayloadDescription": "Routes this device through the SignalTrail debugging proxy.",
                    "PayloadDisplayName": "SignalTrail HTTP Proxy",
                    "PayloadIdentifier": f"{payload_id}.global-http-proxy",
                    "PayloadType": "com.apple.proxy.http.global",
                    "PayloadUUID": str(uuid.uuid4()).upper(),
                    "PayloadVersion": 1,
                    "ProxyCaptiveLoginAllowed": True,
                    "ProxyServer": proxy_host,
                    "ProxyServerPort": proxy_port,
                    "ProxyType": "Manual",
                }
            ],
            "PayloadDescription": "SignalTrail local debugging proxy profile.",
            "PayloadDisplayName": "SignalTrail Proxy",
            "PayloadIdentifier": payload_id,
            "PayloadOrganization": "SignalTrail",
            "PayloadRemovalDisallowed": False,
            "PayloadType": "Configuration",
            "PayloadUUID": str(uuid.uuid4()).upper(),
            "PayloadVersion": 1,
        }
        body = plistlib.dumps(profile)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-apple-aspen-config")
        self.send_header("Content-Disposition", "attachment; filename=signaltrail.mobileconfig")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def dashboard_html(dashboard_port: int) -> str:
    ip = local_ip()
    profile_url = f"http://{ip}:{dashboard_port}/profile.mobileconfig?host={ip}&port=9090"
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={quote(profile_url)}"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SignalTrail</title>
<style>
:root {{ color-scheme: light dark; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
body {{ margin: 0; background: #f6f7f9; color: #17202a; }}
header {{ background: #101820; color: white; padding: 18px 24px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
h1 {{ margin: 0; font-size: 22px; letter-spacing: 0; }}
main {{ padding: 20px 24px 40px; display: grid; gap: 18px; }}
.grid {{ display: grid; grid-template-columns: 320px 1fr; gap: 18px; align-items: start; }}
.panel {{ background: white; border: 1px solid #d8dee6; border-radius: 8px; padding: 16px; }}
.muted {{ color: #5c6773; }}
.stats {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; }}
.stat {{ background: white; border: 1px solid #d8dee6; border-radius: 8px; padding: 14px; }}
.stat strong {{ display: block; font-size: 24px; }}
button, a.button {{ background: #165dff; color: white; border: 0; border-radius: 6px; padding: 10px 12px; text-decoration: none; cursor: pointer; font-weight: 600; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ border-bottom: 1px solid #e4e8ef; padding: 9px 8px; text-align: left; vertical-align: top; }}
th {{ color: #5c6773; font-weight: 700; }}
.tag {{ display: inline-block; background: #eef3ff; color: #174ea6; border-radius: 999px; padding: 2px 7px; margin: 1px; font-size: 12px; }}
.severity-high {{ color: #b42318; }}
.severity-medium {{ color: #9a4d00; }}
.severity-low {{ color: #475569; }}
code {{ background: #edf1f5; padding: 2px 5px; border-radius: 4px; }}
@media (max-width: 900px) {{ .grid, .stats {{ grid-template-columns: 1fr; }} header {{ align-items: flex-start; flex-direction: column; }} }}
</style>
</head>
<body>
<header>
  <div>
    <h1>SignalTrail</h1>
    <div class="muted">Local iPhone traffic timeline and privacy audit</div>
  </div>
  <div>Proxy <code>{ip}:9090</code></div>
</header>
<main>
  <section class="grid">
    <div class="panel">
      <h2>Connect iPhone</h2>
      <p class="muted">Scan to install the iOS proxy profile, or configure Wi-Fi proxy manually.</p>
      <img src="{qr_url}" width="220" height="220" alt="QR code for SignalTrail profile">
      <p><a class="button" href="{profile_url}">Download profile</a></p>
      <p>Manual: iPhone Wi-Fi proxy server <code>{ip}</code>, port <code>9090</code>, authentication off.</p>
    </div>
    <div>
      <div class="stats">
        <div class="stat"><span class="muted">Events</span><strong id="eventsCount">0</strong></div>
        <div class="stat"><span class="muted">Domains</span><strong id="domainsCount">0</strong></div>
        <div class="stat"><span class="muted">Risk</span><strong id="riskScore">0</strong></div>
        <div class="stat"><span class="muted">Sensor Signals</span><strong id="sensorSignals">0</strong></div>
        <div class="stat"><span class="muted">Transferred</span><strong id="bytesCount">0 B</strong></div>
      </div>
      <div class="panel" style="margin-top:18px">
        <h2>Privacy Audit</h2>
        <div id="auditSummary" class="muted"></div>
        <div id="privacySignals"></div>
      </div>
      <div class="panel" style="margin-top:18px">
        <h2>AI Analysis</h2>
        <p><button onclick="refreshAi()">Analyze Now</button></p>
        <pre id="aiAnalysis" class="muted" style="white-space:pre-wrap; font-family:inherit"></pre>
      </div>
      <div class="panel" style="margin-top:18px">
        <h2>Evidence Findings</h2>
        <div id="findings"></div>
      </div>
    </div>
  </section>
  <section class="panel">
    <h2>Live Timeline</h2>
    <p>
      <a class="button" href="/export">Export JSON</a>
      <button onclick="clearEvents()">Clear</button>
    </p>
    <table>
      <thead><tr><th>Time</th><th>Scheme</th><th>Method</th><th>Host</th><th>Path</th><th>Bytes</th><th>Tags</th></tr></thead>
      <tbody id="events"></tbody>
    </table>
  </section>
</main>
<script>
const fmtBytes = (n) => {{
  const units = ["B", "KB", "MB", "GB"];
  let size = n;
  for (const unit of units) {{
    if (size < 1024 || unit === "GB") return unit === "B" ? `${{Math.round(size)}} B` : `${{size.toFixed(1)}} ${{unit}}`;
    size /= 1024;
  }}
}};
async function refresh() {{
  const [events, report] = await Promise.all([fetch("/events").then(r => r.json()), fetch("/report").then(r => r.json())]);
  const totalBytes = events.reduce((sum, e) => sum + (e.bytes_client_to_server || 0) + (e.bytes_server_to_client || 0), 0);
  document.getElementById("eventsCount").textContent = report.event_count;
  document.getElementById("domainsCount").textContent = report.top_domains.length;
  document.getElementById("riskScore").textContent = report.privacy_audit.summary.risk_score;
  document.getElementById("sensorSignals").textContent = report.privacy_audit.summary.sensor_signal_count;
  document.getElementById("bytesCount").textContent = fmtBytes(totalBytes);
  document.getElementById("auditSummary").textContent = `Risk: ${{report.privacy_audit.summary.risk_label}} · Signals: ${{report.privacy_audit.summary.signal_count}}`;
  document.getElementById("privacySignals").innerHTML = report.privacy_audit.signals.length ? report.privacy_audit.signals.map(s =>
    `<p class="severity-${{s.risk}}"><strong>${{s.risk.toUpperCase()}}</strong> ${{s.title}} <span class="tag">${{s.confidence}}</span> <span class="tag">${{s.category}}</span><br><span class="muted">${{s.evidence}}</span></p>`
  ).join("") : '<p class="muted">No privacy signals yet.</p>';
  document.getElementById("findings").innerHTML = report.findings.length ? report.findings.map(f =>
    `<p class="severity-${{f.severity}}"><strong>${{f.severity.toUpperCase()}}</strong> ${{f.title}}<br><span class="muted">${{f.evidence}}</span></p>`
  ).join("") : '<p class="muted">No findings yet.</p>';
  document.getElementById("events").innerHTML = events.slice().reverse().slice(0, 200).map(e => {{
    const ts = new Date(e.started_at * 1000).toLocaleTimeString();
    const tags = (e.tags || []).map(t => `<span class="tag">${{t}}</span>`).join("");
    const bytes = fmtBytes((e.bytes_client_to_server || 0) + (e.bytes_server_to_client || 0));
    return `<tr><td>${{ts}}</td><td>${{e.scheme}}</td><td>${{e.method}}</td><td>${{e.host}}:${{e.port}}</td><td>${{e.path || ""}}</td><td>${{bytes}}</td><td>${{tags}}</td></tr>`;
  }}).join("");
}}
async function clearEvents() {{
  await fetch("/clear", {{ method: "POST" }});
  await refresh();
}}
async function refreshAi() {{
  const ai = await fetch("/ai").then(r => r.json());
  const suffix = ai.note ? `\n\n${{ai.note}}` : "";
  document.getElementById("aiAnalysis").textContent = ai.summary + suffix;
}}
refresh();
refreshAi();
setInterval(refresh, 2000);
</script>
</body>
</html>"""


def qr_fallback_svg(data: str) -> str:
    escaped = data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="420" height="160" viewBox="0 0 420 160">
<rect width="420" height="160" fill="white"/>
<text x="20" y="38" font-family="Arial" font-size="18" fill="#17202a">Open on iPhone:</text>
<text x="20" y="74" font-family="Arial" font-size="13" fill="#17202a">{escaped}</text>
<text x="20" y="118" font-family="Arial" font-size="12" fill="#5c6773">Install optional qrcode support later for offline QR generation.</text>
</svg>"""


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run(proxy_port: int, dashboard_port: int) -> None:
    proxy = ReusableTCPServer(("", proxy_port), ProxyHandler)
    dashboard = ThreadingHTTPServer(("", dashboard_port), DashboardHandler)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    threading.Thread(target=dashboard.serve_forever, daemon=True).start()
    ip = local_ip()
    print(f"SignalTrail dashboard: http://{ip}:{dashboard_port}")
    print(f"iPhone Wi-Fi proxy:   {ip}:{proxy_port}")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nStopping SignalTrail...")
    finally:
        proxy.shutdown()
        dashboard.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="SignalTrail iPhone traffic analyzer")
    parser.add_argument("--proxy-port", type=int, default=9090)
    parser.add_argument("--dashboard-port", type=int, default=8765)
    args = parser.parse_args()
    run(args.proxy_port, args.dashboard_port)
