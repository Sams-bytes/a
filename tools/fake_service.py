"""Pretend to be a service on a port, so you can watch Aegis notice it.

Usage:  .venv\\Scripts\\python tools\\fake_service.py 5432

Listens on 127.0.0.1 only (this computer), so nothing outside can reach it.
Close the window (or Ctrl+C) to make the port disappear again.
"""

import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 5432
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen()
print(f"Fake service listening on 127.0.0.1:{port}. Close this window to stop it.", flush=True)
try:
    while True:
        conn, addr = srv.accept()
        print(f"Someone knocked on port {port} from {addr[0]} (that's Aegis scanning)", flush=True)
        conn.close()
except KeyboardInterrupt:
    pass
