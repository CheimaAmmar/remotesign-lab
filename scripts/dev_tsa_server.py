"""Minimal HTTP transport for a local OpenSSL RFC 3161 test TSA.

This process never implements timestamping itself: every accepted request is
passed to ``openssl ts -reply``, which returns a genuine RFC 3161 response.
The OpenSSL configuration, TSA certificate and private key must live outside
the repository.
"""

import argparse
import subprocess
import tempfile

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


MAX_TIMESTAMP_QUERY_BYTES = 1024 * 1024


class TSARequestHandler(BaseHTTPRequestHandler):
    server_version = "RemoteSignLabDevelopmentTSA/1.0"

    def do_POST(self) -> None:  # noqa: N802 - HTTP handler API
        if self.path != "/":
            self.send_error(404)
            return

        content_type = self.headers.get("Content-Type", "").split(
            ";",
            1,
        )[0].strip().lower()

        if content_type != "application/timestamp-query":
            self.send_error(415)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return

        if not 0 < content_length <= MAX_TIMESTAMP_QUERY_BYTES:
            self.send_error(413)
            return

        query = self.rfile.read(content_length)

        try:
            with tempfile.TemporaryDirectory(
                prefix="remotesign-lab-tsa-"
            ) as directory:
                temporary_directory = Path(directory)
                query_path = temporary_directory / "request.tsq"
                response_path = temporary_directory / "response.tsr"
                query_path.write_bytes(query)
                completed = subprocess.run(
                    [
                        self.server.openssl_binary,
                        "ts",
                        "-reply",
                        "-config",
                        str(self.server.tsa_config),
                        "-section",
                        self.server.tsa_section,
                        "-queryfile",
                        str(query_path),
                        "-out",
                        str(response_path),
                    ],
                    check=False,
                    capture_output=True,
                    timeout=self.server.openssl_timeout,
                )

                if completed.returncode != 0:
                    self.send_error(502)
                    return

                response = response_path.read_bytes()
        except (OSError, subprocess.SubprocessError):
            self.send_error(502)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args) -> None:
        # Keep the standard access log, but never log request bodies.
        super().log_message(format, *args)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Serve a local OpenSSL RFC 3161 development TSA",
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--section", default="tsa_config")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", default=8090, type=int)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--openssl-timeout", default=10.0, type=float)
    args = parser.parse_args()

    config_path = args.config.expanduser().resolve()

    if not config_path.is_file():
        parser.error("the OpenSSL TSA configuration file does not exist")

    server = HTTPServer((args.bind, args.port), TSARequestHandler)
    server.tsa_config = config_path
    server.tsa_section = args.section
    server.openssl_binary = args.openssl
    server.openssl_timeout = args.openssl_timeout

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
