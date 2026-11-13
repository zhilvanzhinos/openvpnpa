"""Actual OpenVPN management smoke test, WITHOUT a tunnel or client traffic."""

import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


@unittest.skipUnless(shutil.which("openvpn") and shutil.which("openssl"), "OpenVPN/openssl unavailable; run Docker lab")
class OpenVPNRuntimeTests(unittest.TestCase):
    def test_management_interface_starts_and_answers_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(root/"key.pem"), "-out", str(root/"cert.pem"),
                "-days", "1", "-subj", "/CN=openvpnpa-lab"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            os.chmod(root/"key.pem", 0o600)
            management = root/"management.sock"
            with (root/"openvpn.log").open("w+") as log:
                process = subprocess.Popen(["openvpn", "--dev", "null", "--proto", "tcp-server",
                    "--tls-server", "--ca", str(root/"cert.pem"), "--cert", str(root/"cert.pem"),
                    "--key", str(root/"key.pem"), "--dh", "none",
                    "--management", str(management), "unix", "--management-hold"],
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic()+10
                    while not management.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.02)
                    if not management.exists():
                        log.seek(0)
                        self.fail("Management socket did not start: "+log.read())
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(5)
                        client.connect(str(management))
                        client.sendall(b"version\n")
                        data = b""
                        while b"END" not in data:
                            chunk = client.recv(8192)
                            if not chunk:
                                break
                            data += chunk
                        self.assertIn(b"OpenVPN Version:", data)
                        self.assertIn(b"Management Version:", data)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
