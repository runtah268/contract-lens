"""ContractLens — stdlib-only HTTP server for free hosting (Render).

Same agent as the Gradio demo (app.py), but with no Gradio dependency,
so it runs on Render's free web-service tier (no card, 750 h/month)
where Hugging Face now gates Gradio Spaces behind PRO.

Endpoints:
  GET  /                HTML form (address or pasted source, optional key)
  GET  /health          {"status": "ok"} — Render health check / judge ping
  POST /api/analyze     JSON in {address, chain, source, api_key}
                        JSON out {score, verdict, report, findings, ...}
  POST /analyze         form-encoded, returns the markdown report as HTML

The Nous API key is accepted per-request only (form field / JSON) or via
the NOUS_API_KEY env var; it is never stored or logged. Without a key
the full deterministic report is still returned.

Run locally:  python3 server.py   (listens on $PORT or 7860)
"""
import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import agent

SAMPLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "sample_token.sol")
try:
    with open(SAMPLE_PATH, encoding="utf-8") as f:
        SAMPLE_SOURCE = f.read()
except OSError:
    SAMPLE_SOURCE = ""

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>ContractLens — understand a contract before you touch it</title>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:2em auto;padding:0 1em}
input,select,textarea{width:100%;padding:.5em;margin:.3em 0 1em}button{padding:.6em 1.2em}
pre{white-space:pre-wrap;background:#f4f4f4;padding:1em;overflow-wrap:anywhere}</style></head>
<body><h1>ContractLens</h1>
<p>Paste a <b>contract address</b> (BSC or Ethereum) or paste <b>Solidity source</b>.
The agent fetches verified source from Sourcify, reads bytecode and owner
from a public RPC, runs 12 static risk checks, and scores the contract 0–100.
With a free Nous API key it also writes a plain-language explanation.
No key is needed for the deterministic report.</p>
<form method="post" action="/analyze">
<label>Contract address (0x…)</label>
<input name="address" placeholder="0x55d398326f99059fF775485246999027B3197955">
<label>Chain</label><select name="chain"><option>BSC</option><option>Ethereum</option></select>
<label>Or paste Solidity source</label>
<textarea name="source" rows="8" placeholder="// paste contract source here"></textarea>
<label>Nous API key (optional, for the AI explanation — never stored)</label>
<input name="api_key" type="password" placeholder="sk-… (free plan, portal.nousresearch.com)">
<button type="submit">Analyze</button></form>
<p><b>Examples:</b> USDT on BSC <code>0x55d398326f99059fF775485246999027B3197955</code>
(score 55 HIGH) · BSCCAT <code>0x9dd4C7D3276609892cF723a90A5AF3f8df40C79A</code>
(score 20 MEDIUM) · paste the sample token source for a CRITICAL 100/100 demo.</p>
<p><b>API:</b> <code>POST /api/analyze</code> with JSON
<code>{"address": "0x…", "chain": "BSC", "source": "", "api_key": ""}</code>
returns <code>{score, verdict, report, findings, …}</code>.</p>
<p><i>Honest limits: a low score never proves a contract is safe or sellable —
it only means these 12 patterns were not found. Unverified contracts cannot
be source-checked; paste the source for the deep check.</i></p>
</body></html>"""


def _run_analysis(address, chain_name, source, api_key):
    chain_id = 56 if (chain_name or "BSC") == "BSC" else 1
    return agent.analyze(
        address=(address or "").strip() or None,
        source=(source or "").strip() or None,
        chain_id=chain_id,
        api_key=(api_key or "").strip() or os.environ.get("NOUS_API_KEY") or None,
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep logs quiet; never log keys/bodies
        pass

    def _send(self, status, body, ctype):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, json.dumps({"status": "ok"}), "application/json")
        elif path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            if path == "/api/analyze":
                payload = json.loads(raw.decode("utf-8") or "{}")
                result = _run_analysis(payload.get("address"), payload.get("chain"),
                                       payload.get("source"), payload.get("api_key"))
                self._send(200, json.dumps(result, default=str), "application/json")
            elif path == "/analyze":
                form = parse_qs(raw.decode("utf-8"))
                get = lambda k: (form.get(k) or [""])[0]
                result = _run_analysis(get("address"), get("chain"),
                                       get("source"), get("api_key"))
                body = ("<h1>ContractLens report</h1><pre>"
                        + html.escape(result["report"])
                        + '</pre><p><a href="/">← Analyze another contract</a></p>')
                self._send(200, body, "text/html; charset=utf-8")
            else:
                self._send(404, "not found", "text/plain")
        except ValueError as e:
            self._send(400, json.dumps({"error": str(e)}), "application/json")
        except Exception as e:  # noqa: BLE001 - show the error, don't crash
            self._send(500, json.dumps({"error": str(e)}), "application/json")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "7860"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
