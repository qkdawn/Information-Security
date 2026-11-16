"""Convenience launcher with paths independent of the working directory."""

from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1] / "py-http-server"
sys.path.insert(0, str(PROJECT))

from py_http_server import app_main
from py_http_server.middlewares import DefaultMiddleware
from py_http_server.middlewares.digest_auth import DigestAuthMiddleware
from py_http_server.networking import TCPAddress
from py_http_server.routers import FileRouter


if __name__ == "__main__":
    # Explicit paths make this launcher independent of the current directory.
    app_main(
        handler_chain=DefaultMiddleware(
            DigestAuthMiddleware(
                next=FileRouter(str(PROJECT)), pwdfile=str(PROJECT / "passwords.txt")
            )
        ),
        http_listeners=[TCPAddress("127.0.0.1", 8080), TCPAddress("::1", 8080)],
        log_level="INFO",
    )
