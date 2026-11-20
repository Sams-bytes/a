"""Pretend to be a service on a port, so you can watch Aegis notice it.

Usage:
  .venv\\Scripts\\python tools\\fake_service.py 5432
  .venv\\Scripts\\python tools\\fake_service.py 21 --banner "220 ProFTPD 1.3.5 Server"

--banner makes it greet every visitor like real software does, so Aegis can
fingerprint the "software" and look up its CVEs. It is only a greeting - there
is no real (or vulnerable) program behind it.

Listens on 127.0.0.1 only (this computer), so nothing outside can reach it.
Close the window (or Ctrl+C) to make the port disappear again.
"""

import argparse
import socket

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int, nargs="?", default=5432)
ap.add_argument("--banner", default="", help='greeting to send, e.g. "220 ProFTPD 1.3.5 Server"')
args = ap.parse_args()

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", args.port))
srv.listen()
print(f"Fake service listening on 127.0.0.1:{args.port}"
      + (f" and greeting with: {args.banner}" if args.banner else "")
      + ". Close this window to stop it.", flush=True)
try:
    while True:
        conn, addr = srv.accept()
        print(f"Someone knocked on port {args.port} from {addr[0]} (that's Aegis scanning)", flush=True)
        if args.banner:
            try:
                conn.sendall(args.banner.encode() + b"\r\n")
            except OSError:
                pass
        conn.close()
except KeyboardInterrupt:
    pass
