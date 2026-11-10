import pytest

from cert_expiry_watch.sources import (
    Target,
    expand_pem_paths,
    load_pem_file,
    parse_target,
    read_hosts_file,
)
from conftest import make_cert


@pytest.mark.parametrize(
    "text, expected",
    [
        ("example.com", Target("example.com", 443)),
        ("example.com:8443", Target("example.com", 8443)),
        ("  example.com:8443  ", Target("example.com", 8443)),
        ("https://example.com/path?q=1", Target("example.com", 443)),
        ("https://example.com:9443/", Target("example.com", 9443)),
        ("10.0.0.5:6443", Target("10.0.0.5", 6443)),
        ("[::1]:8443", Target("::1", 8443)),
        ("[2001:db8::1]", Target("2001:db8::1", 443)),
        ("2001:db8::1", Target("2001:db8::1", 443)),
    ],
)
def test_parse_target(text, expected):
    assert parse_target(text) == expected


@pytest.mark.parametrize("text", ["", "https://", "host:abc", "host:0", "host:70000", ":443", "[::1", "[::1]x"])
def test_parse_target_rejects_bad_input(text):
    with pytest.raises(ValueError):
        parse_target(text)


def test_target_label_brackets_ipv6():
    assert Target("example.com", 8443).label == "example.com:8443"
    assert Target("::1", 443).label == "[::1]:443"


def test_read_hosts_file_skips_comments_and_blanks(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("# production\nexample.com\n\napi.example.com:8443  # gateway\n   \n")
    assert read_hosts_file(hosts) == [Target("example.com"), Target("api.example.com", 8443)]


def test_read_hosts_file_reports_line_number(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("example.com\nbad:port\n")
    with pytest.raises(ValueError, match=r"hosts\.txt:2: invalid port"):
        read_hosts_file(hosts)


def test_load_pem_file_reads_chain_and_ignores_private_key(tmp_path):
    leaf, key = make_cert("leaf.local")
    intermediate, _ = make_cert("intermediate.local")
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(key + leaf + intermediate)
    certs = load_pem_file(bundle)
    assert len(certs) == 2


def test_load_pem_file_without_certificate(tmp_path):
    _, key = make_cert()
    path = tmp_path / "only-key.pem"
    path.write_bytes(key)
    with pytest.raises(ValueError, match="no PEM certificate"):
        load_pem_file(path)


def test_expand_pem_paths(tmp_path):
    for name in ("b.pem", "a.crt", "c.cer", "notes.txt", "key.key"):
        (tmp_path / name).write_text("x")
    (tmp_path / "sub").mkdir()
    single = tmp_path / "notes.txt"
    result = expand_pem_paths([str(tmp_path), str(single), "missing.pem"])
    assert [p.name for p in result] == ["a.crt", "b.pem", "c.cer", "notes.txt", "missing.pem"]
