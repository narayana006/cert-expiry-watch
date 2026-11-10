from datetime import timedelta

import pytest
from cryptography import x509

from cert_expiry_watch.check import (
    Result,
    check_file,
    check_host,
    evaluate,
    exit_code,
    run_checks,
    summarise,
)
from cert_expiry_watch.sources import Target
from conftest import NOW, make_cert


def cert(**kwargs):
    return x509.load_pem_x509_certificate(make_cert(**kwargs)[0])


@pytest.mark.parametrize(
    "days_left, warn_days, status, days_remaining",
    [
        (90, 21, "ok", 90),
        (21, 21, "ok", 21),  # exactly at the threshold is not yet inside the window
        (20.5, 21, "expiring", 20),
        (0.5, 21, "expiring", 0),
        (0, 21, "expired", 0),
        (-0.5, 21, "expired", -1),
        (-400, 21, "expired", -400),
        (5, 0, "ok", 5),  # --warn-days 0 only flags expired certificates
        (90, 120, "expiring", 90),
    ],
)
def test_evaluate_status_and_days(days_left, warn_days, status, days_remaining):
    result = evaluate(cert(days_left=days_left), "x", "file", NOW, warn_days)
    assert result.status == status
    assert result.days_remaining == days_remaining


def test_evaluate_reports_subject_issuer_expiry_and_san():
    result = evaluate(cert(common_name="api.local", issuer_name="Corp CA", days_left=10), "src", "file", NOW, 21)
    assert result.subject == "api.local"
    assert result.issuer == "Corp CA"
    assert result.not_after == (NOW + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert result.san == ["api.local", "127.0.0.1"]
    assert evaluate(cert(san=False), "src", "file", NOW, 21).san == []


def test_check_host_reads_certificate_from_live_tls_server(tls_server):
    port = tls_server(common_name="live.local", days_left=10)
    result = check_host(Target("127.0.0.1", port), NOW, warn_days=21)
    assert result.status == "expiring"
    assert result.subject == "live.local"
    assert result.days_remaining == 10
    assert result.source == f"127.0.0.1:{port}"
    assert result.kind == "host"


def test_check_host_can_read_an_already_expired_certificate(tls_server):
    port = tls_server(common_name="old.local", days_left=-30)
    result = check_host(Target("127.0.0.1", port), NOW, warn_days=21)
    assert result.status == "expired"
    assert result.days_remaining == -30


def test_check_host_connection_refused_is_an_error_result(closed_port):
    result = check_host(Target("127.0.0.1", closed_port), NOW, warn_days=21, timeout=2)
    assert result.status == "error"
    assert result.error
    assert result.days_remaining is None


def test_check_host_with_injected_fetcher_failure():
    def fetch(target, timeout):
        raise TimeoutError("timed out")

    result = check_host(Target("slow.example", 443), NOW, 21, fetch=fetch)
    assert (result.status, result.error) == ("error", "timed out")


def test_check_file_chain_and_errors(tmp_path):
    bundle = tmp_path / "chain.pem"
    bundle.write_bytes(make_cert("leaf.local", days_left=5)[0] + make_cert("ca.local", days_left=900)[0])
    results = check_file(bundle, NOW, 21)
    assert [(r.source, r.status) for r in results] == [
        (f"{bundle}#1", "expiring"),
        (f"{bundle}#2", "ok"),
    ]

    garbage = tmp_path / "garbage.pem"
    garbage.write_text("not a certificate")
    assert check_file(garbage, NOW, 21)[0].status == "error"

    missing = check_file(tmp_path / "missing.pem", NOW, 21)[0]
    assert missing.status == "error"
    assert "No such file" in missing.error


def test_run_checks_mixes_hosts_and_files_most_urgent_first(tls_server, closed_port, tmp_path):
    good = tls_server(common_name="good.local", days_left=200)
    soon = tls_server(common_name="soon.local", days_left=3)
    pem = tmp_path / "old.pem"
    pem.write_bytes(make_cert("old.local", days_left=-10)[0])
    targets = [Target("127.0.0.1", good), Target("127.0.0.1", soon), Target("127.0.0.1", closed_port)]
    results = run_checks(targets, [pem], warn_days=21, timeout=2, now=NOW)
    assert [r.status for r in results] == ["error", "expired", "expiring", "ok"]
    assert [r.subject for r in results[1:]] == ["old.local", "soon.local", "good.local"]
    assert summarise(results) == {"ok": 1, "expiring": 1, "expired": 1, "error": 1}


def test_exit_code_precedence():
    ok = Result("a", "file", "ok")
    expiring = Result("b", "file", "expiring")
    expired = Result("c", "file", "expired")
    error = Result("d", "host", "error", error="boom")
    assert exit_code([ok]) == 0
    assert exit_code([ok, expiring]) == 1
    assert exit_code([ok, expired]) == 1
    assert exit_code([ok, error]) == 2
    assert exit_code([error, expiring]) == 1
    assert exit_code([]) == 0
