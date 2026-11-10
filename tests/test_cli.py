import io
import json

import pytest

from cert_expiry_watch.cli import main
from conftest import NOW, make_cert


def run(argv):
    out = io.StringIO()
    code = main(argv, stdout=out, now=NOW)
    return code, out.getvalue()


@pytest.fixture
def pems(tmp_path):
    paths = {}
    for name, days in (("ok", 300), ("soon", 10), ("old", -5)):
        path = tmp_path / f"{name}.pem"
        path.write_bytes(make_cert(f"{name}.local", days_left=days)[0])
        paths[name] = str(path)
    return paths


def test_hosts_file_and_pem_together_json(tls_server, tmp_path, pems):
    port = tls_server(common_name="live.local", days_left=40)
    hosts = tmp_path / "hosts.txt"
    hosts.write_text(f"# local test server\n127.0.0.1:{port}\n")
    code, out = run(["--hosts", str(hosts), "--pem", pems["soon"], "--warn-days", "21", "--json"])
    assert code == 1
    data = json.loads(out)
    assert data["checked_at"] == "2025-06-01T12:00:00Z"
    assert data["warn_days"] == 21
    assert data["summary"] == {"ok": 1, "expiring": 1, "expired": 0, "error": 0}
    soon, live = data["results"]
    assert (soon["subject"], soon["status"], soon["days_remaining"], soon["kind"]) == ("soon.local", "expiring", 10, "file")
    assert (live["subject"], live["status"], live["days_remaining"], live["kind"]) == ("live.local", "ok", 40, "host")
    assert live["issuer"] == "Test Issuer"
    assert live["not_after"] == "2025-07-11T12:00:00Z"


def test_warn_days_changes_the_verdict(tls_server):
    port = tls_server(days_left=40)
    assert run([f"127.0.0.1:{port}"])[0] == 0
    assert run([f"127.0.0.1:{port}", "--warn-days", "60"])[0] == 1


def test_text_table(pems):
    code, out = run(["--pem", pems["ok"], "--pem", pems["old"], "--pem", pems["soon"]])
    assert code == 1
    lines = out.splitlines()
    assert lines[0].split() == ["STATUS", "DAYS", "EXPIRES", "(UTC)", "SUBJECT", "ISSUER", "SOURCE"]
    assert [line.split()[0] for line in lines[1:4]] == ["EXPIRED", "EXPIRING", "OK"]
    assert lines[1].split()[1:4] == ["-5", "2025-05-27", "12:00"]
    assert lines[-1] == "3 checked: 1 ok, 1 expiring within 21 days, 1 expired, 0 could not be checked"


def test_directory_of_pems_all_ok_exits_zero(tmp_path):
    for name in ("a.pem", "b.crt"):
        (tmp_path / name).write_bytes(make_cert(name, days_left=100)[0])
    (tmp_path / "README.txt").write_text("ignored")
    code, out = run(["--pem", str(tmp_path)])
    assert code == 0
    assert "2 checked: 2 ok" in out


def test_unreachable_host_exits_two_and_is_listed(closed_port, pems):
    code, out = run([f"127.0.0.1:{closed_port}", "--pem", pems["ok"], "--timeout", "2"])
    assert code == 2
    assert out.splitlines()[1].startswith("ERROR")
    assert "1 could not be checked" in out


def test_usage_errors(tmp_path, capsys):
    bad_hosts = tmp_path / "hosts.txt"
    bad_hosts.write_text("host:notaport\n")
    for argv in ([], ["--warn-days", "-1", "x"], ["--timeout", "0", "x"], ["--hosts", str(bad_hosts)], ["--hosts", "/nonexistent/hosts.txt"]):
        with pytest.raises(SystemExit) as exc:
            run(argv)
        assert exc.value.code == 2
    assert "nothing to check" in capsys.readouterr().err
