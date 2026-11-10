"""Work out how long each certificate has left and classify it."""

from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.x509.oid import NameOID

from .sources import Target, fetch_certificate, load_pem_file

OK = "ok"
EXPIRING = "expiring"
EXPIRED = "expired"
ERROR = "error"


@dataclass
class Result:
    """The outcome of checking one certificate (or failing to)."""

    source: str
    kind: str  # "host" or "file"
    status: str
    subject: str | None = None
    issuer: str | None = None
    not_after: str | None = None  # ISO 8601, UTC
    days_remaining: int | None = None
    san: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _display_name(name: x509.Name) -> str:
    """Prefer the common name; fall back to the organisation or full DN."""
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        values = name.get_attributes_for_oid(oid)
        if values:
            return str(values[0].value)
    return name.rfc4514_string() or "(empty)"


def _san(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names = [str(n) for n in extension.value.get_values_for_type(x509.DNSName)]
    names += [str(ip) for ip in extension.value.get_values_for_type(x509.IPAddress)]
    return names


def evaluate(
    cert: x509.Certificate, source: str, kind: str, now: datetime, warn_days: int
) -> Result:
    """Classify a certificate as ok, expiring or expired at time ``now``.

    ``days_remaining`` is rounded down, and is negative once the certificate
    has expired. A certificate is *expiring* when it has less than
    ``warn_days`` whole days left.
    """
    not_after = cert.not_valid_after_utc
    remaining = not_after - now
    if remaining <= timedelta(0):
        status = EXPIRED
    elif remaining < timedelta(days=warn_days):
        status = EXPIRING
    else:
        status = OK
    return Result(
        source=source,
        kind=kind,
        status=status,
        subject=_display_name(cert.subject),
        issuer=_display_name(cert.issuer),
        not_after=not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        days_remaining=math.floor(remaining.total_seconds() / 86400),
        san=_san(cert),
    )


def check_host(
    target: Target,
    now: datetime,
    warn_days: int,
    timeout: float = 5.0,
    fetch: Callable[[Target, float], x509.Certificate] = fetch_certificate,
) -> Result:
    try:
        cert = fetch(target, timeout)
    except Exception as exc:  # DNS, refused, timeout, TLS failure, bad certificate
        message = str(exc) or type(exc).__name__
        return Result(source=target.label, kind="host", status=ERROR, error=message)
    return evaluate(cert, target.label, "host", now, warn_days)


def check_file(path: Path, now: datetime, warn_days: int) -> list[Result]:
    """Check every certificate in a PEM file; a chain yields several results."""
    try:
        certs = load_pem_file(path)
    except Exception as exc:
        message = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
        return [Result(source=str(path), kind="file", status=ERROR, error=message)]
    results = []
    for index, cert in enumerate(certs, 1):
        source = str(path) if len(certs) == 1 else f"{path}#{index}"
        results.append(evaluate(cert, source, "file", now, warn_days))
    return results


def run_checks(
    targets: list[Target],
    files: list[Path],
    warn_days: int,
    timeout: float = 5.0,
    now: datetime | None = None,
    workers: int = 16,
) -> list[Result]:
    """Check all hosts (in parallel) and files, most urgent first."""
    now = now or datetime.now(timezone.utc)
    results: list[Result] = []
    if targets:
        with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
            results.extend(pool.map(lambda t: check_host(t, now, warn_days, timeout), targets))
    for path in files:
        results.extend(check_file(path, now, warn_days))
    return sorted(results, key=_urgency)


def _urgency(result: Result) -> tuple:
    if result.status == ERROR:
        return (0, 0, result.source)
    return (1, result.days_remaining, result.source)


def summarise(results: list[Result]) -> dict[str, int]:
    counts = {OK: 0, EXPIRING: 0, EXPIRED: 0, ERROR: 0}
    for result in results:
        counts[result.status] += 1
    return counts


def exit_code(results: list[Result]) -> int:
    """0 = all fine, 1 = something expired or expiring, 2 = only check errors."""
    counts = summarise(results)
    if counts[EXPIRED] or counts[EXPIRING]:
        return 1
    if counts[ERROR]:
        return 2
    return 0
