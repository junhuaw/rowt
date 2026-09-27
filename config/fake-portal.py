#!/usr/bin/env python3
"""A fake captive portal, for testing rowt's captive handling without an airport.

Serves three endpoints on 127.0.0.1 (port = argv[1], default 8099), one per
portal behavior the watchdog's classifier must handle (DESIGN.md §11):

  /portal    200 with a lounge-style login page   -> _captive_state = captive
  /redirect  302 to a portal host                 -> _captive_state = captive
  /success   the genuine Apple Success body       -> _captive_state = clear
  /aruba     200 whose only URL is a query-carrying refresh back to THIS host,
             the Aruba ClearPass/Instant shape; the hop it names answers 302
             with the portal's real address     -> _captive_state = captive

The /portal and /aruba bodies carry a URL on purpose: naming the portal's own
host is half of what the watchdog does with them (DESIGN.md §11). /aruba also
checks that `&amp;` was decoded the way a browser decodes it — the hop replies
400 if it was sent through literally.

Point the watchdog's probe at it and run real ticks (NOTE: this toggles the
real system proxy for a few seconds — run it when that's acceptable):

  ROWT_CAPTIVE_URL=http://127.0.0.1:8099/portal  bash bin/rowt watch tick   # drops the proxy
  ROWT_CAPTIVE_URL=http://127.0.0.1:8099/portal  bash bin/rowt watch tick   # idempotent: no new log lines
  ROWT_CAPTIVE_URL=http://127.0.0.1:9/x          bash bin/rowt watch tick   # unknown: stays hands-off
  ROWT_CAPTIVE_URL=http://127.0.0.1:8099/success bash bin/rowt watch tick   # restores the proxy

Stdlib only; nothing is written to disk.
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

SUCCESS = b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
PORTAL = (
    b'<HTML><HEAD><META http-equiv="refresh" content="0;'
    b'url=http://portal.fakelounge.example/login?mac=aa-bb&ip=198.51.100.9">'
    b"</HEAD><BODY>Welcome to FakeLounge - please log in</BODY></HTML>"
)
# The one hop the portal names, and the only query the watchdog may follow.
ARUBA_QUERY = "?cmd=redirect&arubalp=7"
ARUBA_LOGIN = (
    "https://portal.fakearuba.example/guest/login.php"
    "?cmd=login&mac=aa-bb&ip=198.51.100.9&essid=FakeWifi"
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://portal.fake/login")
            self.end_headers()
            return
        if self.path.startswith("/aruba?"):
            # Only the DECODED query is the hop. A literal `&amp;` here means
            # the follower passed the HTML through without decoding it.
            ok = self.path == "/aruba" + ARUBA_QUERY
            self.send_response(302 if ok else 400)
            if ok:
                self.send_header("Location", ARUBA_LOGIN)
            self.end_headers()
            return
        if self.path == "/aruba":
            port = self.server.server_address[1]
            body = (
                '<HTML><HEAD><META http-equiv="refresh" content="0;'
                f"url=http://127.0.0.1:{port}/aruba"
                f'{ARUBA_QUERY.replace("&", "&amp;")}">'
                "</HEAD><BODY>Wireless Network Login</BODY></HTML>"
            ).encode()
        else:
            body = PORTAL if self.path == "/portal" else SUCCESS
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print(
        f"fake portal on http://127.0.0.1:{port}  (/portal /redirect /success /aruba)"
    )
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
