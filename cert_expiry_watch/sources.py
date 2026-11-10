"""Where certificates come from: live TLS endpoints and PEM files on disk."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

DEFAULT_PORT = 443
PEM_SUFFIXES = (".pem", ".crt", ".cer")


@dataclass(frozen=True)
class Target:
    """A TLS endpoint to connect to."""

    host: str
    port: int = DEFAULT_PORT

    @property
    def label(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def parse_target(text: str) -> Target:
    """Parse ``host``, ``host:port``, ``[ipv6]:port`` or an https:// URL."""
    value = text.strip()
    if value.lower().startswith("https://"):
        value = value[len("https://") :]
    value = value.split("/", 1)[0]
    if not value:
        raise ValueError(f"empty host in {text!r}")

    host, port_text = value, ""
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError(f"missing ']' in {text!r}")
        host, rest = value[1:end], value[end + 1 :]
        if rest and not rest.startswith(":"):
            raise ValueError(f"unexpected text after ']' in {text!r}")
        port_text = rest[1:]
    elif value.count(":") == 1:
        host, port_text = value.split(":")
    # More than one colon without brackets is a bare IPv6 address.

    if not host:
        raise ValueError(f"empty host in {text!r}")
    if not port_text:
        return Target(host)
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise ValueError(f"invalid port in {text!r}")
    return Target(host, int(port_text))


def read_hosts_file(path: str | Path) -> list[Target]:
    """Read one target per line. Blank lines and ``#`` comments are ignored."""
    targets: list[Target] = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                targets.append(parse_target(entry))
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: {exc}") from None
    return targets


def fetch_certificate(target: Target, timeout: float = 5.0) -> x509.Certificate:
    """Connect to the target and return the leaf certificate it presents.

    Verification is deliberately switched off: an expired, self-signed or
    mismatched certificate is exactly what this tool needs to be able to
    read. Nothing is sent over the connection after the handshake.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=target.host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("server presented no certificate")
    return x509.load_der_x509_certificate(der)


def load_pem_file(path: str | Path) -> list[x509.Certificate]:
    """Return every certificate in a PEM file (a file may hold a chain).

    Only CERTIFICATE blocks are parsed; private keys in the same file are
    ignored. Raises ValueError if the file contains no certificate.
    """
    data = Path(path).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" not in data:
        raise ValueError("no PEM certificate found in file")
    return x509.load_pem_x509_certificates(data)


def expand_pem_paths(paths: list[str]) -> list[Path]:
    """Turn files and directories into a list of files to read.

    A directory contributes the ``.pem``, ``.crt`` and ``.cer`` files directly
    inside it. Paths that do not exist are kept so the caller can report them.
    """
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(
                sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() in PEM_SUFFIXES)
            )
        else:
            files.append(path)
    return files
