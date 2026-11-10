"""Test helpers: throwaway certificates and a local TLS server.

Everything here is generated on the fly and bound to 127.0.0.1; the test
suite never contacts an external host.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_cert(common_name="test.local", days_left=90.0, issuer_name="Test Issuer", san=True, now=NOW):
    """Return (certificate PEM, private key PEM) expiring ``days_left`` days after ``now``."""
    key = ec.generate_private_key(ec.SECP256R1())
    not_after = now + timedelta(days=days_left)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(min(now, not_after) - timedelta(days=30))
        .not_valid_after(not_after)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


class TLSServer:
    """Minimal TLS server that completes the handshake and hangs up."""

    def __init__(self, certfile, keyfile):
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certfile, keyfile)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                with self._context.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    def close(self):
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def tls_server(tmp_path):
    """Factory: tls_server(days_left=..., common_name=...) -> port."""
    servers = []

    def start(**cert_args):
        cert_pem, key_pem = make_cert(**cert_args)
        index = len(servers)
        certfile, keyfile = tmp_path / f"srv{index}.pem", tmp_path / f"srv{index}.key"
        certfile.write_bytes(cert_pem)
        keyfile.write_bytes(key_pem)
        server = TLSServer(certfile, keyfile)
        servers.append(server)
        return server.port

    yield start
    for server in servers:
        server.close()


@pytest.fixture
def closed_port():
    """A port on 127.0.0.1 that nothing is listening on."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
