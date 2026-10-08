"""Exercise online CRL/OCSP against a loopback responder; never access the Internet."""

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import tempfile
import threading


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-tool", required=True)
    parser.add_argument("--analyzer", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pesign-online-") as temporary:
        directory = pathlib.Path(temporary)
        state = {"mode": "ocsp", "post": 0, "get": 0, "aia": 0}

        class Responder(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format, *arguments):
                pass

            def respond(self, payload, content_type):
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self):
                state["post"] += 1
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                if not body or body[0] != 0x30 or self.path not in ("/ocsp/root", "/ocsp/issuer"):
                    self.send_error(400)
                    return
                if state["mode"] == "crl":
                    self.send_error(503)
                    return
                name = "root.ocsp" if self.path.endswith("/root") else "issuer.ocsp"
                if state["mode"] == "revoked" and self.path.endswith("/issuer"):
                    name = "revoked.ocsp"
                self.respond((directory / name).read_bytes(), "application/ocsp-response")

            def do_GET(self):
                state["get"] += 1
                if self.path == "/intermediate.der":
                    state["aia"] += 1
                    self.respond((directory / "intermediate.der").read_bytes(), "application/pkix-cert")
                    return
                if self.path not in ("/root.crl", "/issuer.crl"):
                    self.send_error(404)
                    return
                if state["mode"] in ("ocsp", "revoked"):
                    self.send_error(503)  # Force the verifier to exercise OCSP after CRL retrieval fails.
                    return
                self.respond((directory / self.path.lstrip("/")).read_bytes(), "application/pkix-crl")

        responder = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Responder)
        responder.daemon_threads = True
        port = responder.server_address[1]
        environment = os.environ.copy()
        for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            environment.pop(name, None)
        environment["NO_PROXY"] = "127.0.0.1,localhost"
        subprocess.run(
            [args.fixture_tool, "--export-online", str(directory), f"http://127.0.0.1:{port}"],
            env=environment, check=True, timeout=40,
        )
        worker = threading.Thread(target=responder.serve_forever, daemon=True)
        worker.start()

        def analyze(mode, cache, expected, file="signed.exe"):
            command = [
                args.analyzer, "--verify", "--json", "--no-system-roots", "--ca-file", str(directory / "root.pem"),
                "--revocation", mode, "--revocation-cache", str(directory / cache),
                "--network-timeout", "2", str(directory / file),
            ]
            result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=25)
            check(bool(result.stdout.strip()), f"CLI returned no JSON: {result.stderr}")
            document = json.loads(result.stdout)
            verification = document.get("verification", {})
            if isinstance(verification, str):
                verification = document["signatures"][0]["signers"][0]["verification"]
            check(verification.get("revocation") == expected,
                  f"expected {expected}, received {verification}: {result.stderr}")
            if expected == "good":
                check(result.returncode == 0 and verification.get("overall") == "valid",
                      f"good online validation failed: {verification}")
            else:
                check(result.returncode != 0 and verification.get("overall") != "valid",
                      f"invalid online signer was accepted: {verification}")

        try:
            analyze("online", "ocsp-cache", "good")
            check(state["post"] >= 2, "online mode did not request OCSP for both leaf and intermediate")
            before = dict(state)
            analyze("cache", "ocsp-cache", "good")
            check(state == before, "cache-only mode accessed the network")

            aia_cache = directory / "aia-cache"
            aia_cache.mkdir()
            issuer_url = f"http://127.0.0.1:{port}/intermediate.der"
            issuer_key = hashlib.sha256(("issuer:" + issuer_url).encode("utf-8")).hexdigest() + ".cer"
            (aia_cache / issuer_key).write_bytes((directory / "wrong-intermediate.der").read_bytes())
            analyze("online", "aia-cache", "good", "missing-issuer.exe")
            check(state["aia"] >= 1, "online chain building did not retrieve its missing AIA intermediate")
            before = dict(state)
            analyze("cache", "aia-cache", "good", "missing-issuer.exe")
            check(state == before, "cached AIA intermediate was not reused offline")
            analyze("none", "aia-cache", "not_checked", "missing-issuer.exe")
            check(state == before, "revocation-none mode accessed AIA or revocation endpoints")

            state["mode"] = "crl"
            before_get = state["get"]
            analyze("online", "crl-cache", "good")
            check(state["get"] >= before_get + 2, "online mode did not retrieve both issuer CRLs")
            before = dict(state)
            analyze("cache", "crl-cache", "good")
            check(state == before, "cached CRLs were not reused offline")

            state["mode"] = "revoked"
            analyze("online", "revoked-cache", "revoked")
        finally:
            responder.shutdown()
            responder.server_close()
            worker.join(timeout=5)

        analyze("cache", "ocsp-cache", "good")
        print("PASS online OCSP, CRL, AIA, revoked response, and offline cache reuse")


if __name__ == "__main__":
    main()
