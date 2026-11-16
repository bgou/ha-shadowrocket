"""Minimal Supervisor API mock: /dns/info, /dns/options, /network/info. State in $MOCK_STATE (json)."""
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
ST = os.environ["MOCK_STATE"]
def load(): return json.load(open(ST))
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, data): b = json.dumps({"result": "ok", "data": data}).encode(); self.send_response(200); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        s = load()
        if self.headers.get("Authorization") != "Bearer testtoken": self.send_response(401); self.end_headers(); return
        if self.path == "/dns/info": self._send({"servers": s["servers"], "locals": ["dns://127.0.0.1:5399"], "fallback": True})
        elif self.path == "/network/info": self._send({"docker": {"gateway": "127.0.0.2"}})
        else: self.send_response(404); self.end_headers()
    def do_POST(self):
        s = load(); body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/dns/options":
            s["servers"] = body["servers"]; s.setdefault("history", []).append(body["servers"]); json.dump(s, open(ST, "w")); self._send({})
        else: self.send_response(404); self.end_headers()
HTTPServer(("127.0.0.1", 8099), H).serve_forever()
