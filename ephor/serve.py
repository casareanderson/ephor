"""A read-only HTML view, built on nothing but the standard library's http.server.

This is a convenience, not a product surface: no auth, no write endpoints, no JS framework — one page that
renders the same data the CLI shows. Bind it to localhost (the default) or a trusted LAN address only; it is
not hardened for exposure to the internet, and it never mutates state. If you need an authenticated, shared
dashboard, put this behind your own reverse proxy and SSO, the same as any other internal tool.
"""
from __future__ import annotations

import html
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, store


def _age(ts: int) -> str:
    if not ts:
        return "never"
    d = int(time.time()) - ts
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{d // n}{unit} ago"
    return f"{d}s ago"


def _bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


_CSS = """
body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0f1115;color:#d7dae0}
header{padding:16px 20px;background:#161922;border-bottom:1px solid #262b36}
h1{font-size:18px;margin:0}h2{font-size:15px;margin:22px 20px 8px;color:#9aa4b2}
.sub{color:#6b7382;font-size:12px}table{border-collapse:collapse;width:calc(100% - 40px);margin:0 20px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #20242e}
th{color:#7d8694;font-weight:600;font-size:12px;text-transform:uppercase}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.bad{color:#ff6b6b;font-weight:600}.ok{color:#5bd68a}
footer{padding:16px 20px;color:#6b7382;font-size:12px}
@media(max-width:600px){table{width:calc(100% - 20px);margin:0 10px;font-size:12px}}
"""


def _page() -> str:
    db = store.connect()
    st = store.stats(db)
    agents = store.agents(db)
    bad = store.history(db, bad_only=True, limit=100)
    db.close()
    rows = "".join(
        f"<tr><td>{html.escape(a['agent'])}</td><td class=n>{a['dests']}</td>"
        f"<td class=n>{_bytes(a['bytes_recv'])}</td>"
        f"<td class=n>{'<span class=bad>'+str(a['bad_dests'])+'</span>' if a['bad_dests'] else '0'}</td>"
        f"<td>{_age(a['last_seen'])}</td></tr>"
        for a in agents
    ) or "<tr><td colspan=5 class=sub>no agents recorded yet</td></tr>"
    badrows = "".join(
        f"<tr><td>{html.escape(b['agent'])}</td><td>{html.escape(b['dest'])}</td>"
        f"<td class=bad>{html.escape(b['feed'])}</td><td>{_age(b['last_seen'])}</td></tr>"
        for b in bad
    ) or "<tr><td colspan=4 class=ok>no known-bad destinations seen</td></tr>"
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Ephor</title><style>{_CSS}</style></head><body>
<header><h1>Ephor <span class=sub>v{__version__} · detect-only</span></h1>
<div class=sub>{st['agents']} agents · {st['destinations']} destinations ·
<span class="{'bad' if st['bad_destinations'] else 'ok'}">{st['bad_destinations']} known-bad</span> ·
last sample {_age(st['last_sample'])}</div></header>
<h2>Agents</h2>
<table><tr><th>Agent</th><th>Dests</th><th>Downloaded</th><th>Bad</th><th>Last seen</th></tr>{rows}</table>
<h2>Known-bad destinations</h2>
<table><tr><th>Agent</th><th>Destination</th><th>Feed</th><th>Last seen</th></tr>{badrows}</table>
<footer>Read-only. Ephor never blocks traffic. Refresh to update.</footer>
</body></html>"""


class _H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        body = _page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quiet
        pass


def run(host: str, port: int) -> int:
    srv = ThreadingHTTPServer((host, port), _H)
    print(f"ephor serve: http://{host}:{port}  (read-only, Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0
