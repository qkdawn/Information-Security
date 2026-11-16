"""Check that the unmodified server can serve a file over loopback HTTP."""

from pathlib import Path
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


def main():
    project = Path(__file__).resolve().parents[1] / "py-http-server"
    expected = (project / "README.md").read_bytes()
    # Pick an available local port without using the assignment's port 8080.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    server_code = (
        "from py_http_server import app_main; "
        "from py_http_server.middlewares import DefaultMiddleware; "
        "from py_http_server.routers import FileRouter; "
        "from py_http_server.networking import TCPAddress; "
        "app_main(handler_chain=DefaultMiddleware(FileRouter('.')), "
        f"http_listeners=[TCPAddress('127.0.0.1', {port})], log_level='ERROR')"
    )
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    process = subprocess.Popen(
        [sys.executable, "-c", server_code],
        cwd=project,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Bypass system proxy settings for this local-only check.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        deadline = time.monotonic() + 10
        while True:
            if process.poll() is not None:
                output, errors = process.communicate()
                raise RuntimeError(
                    "Server exited before it was ready:\n"
                    + (output + errors).decode("utf-8", "replace")
                )
            try:
                with opener.open(
                    f"http://127.0.0.1:{port}/README.md", timeout=2
                ) as response:
                    if response.status != 200 or response.read() != expected:
                        raise RuntimeError("Unexpected status or file contents")
                break
            except urllib.error.HTTPError:
                raise
            except (urllib.error.URLError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Server did not become ready within 10 seconds")
                time.sleep(0.1)
        print("PASS: server returned HTTP 200 with the expected file contents.")
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


if __name__ == "__main__":
    main()
