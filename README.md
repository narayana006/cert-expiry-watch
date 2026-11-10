# cert-expiry-watch

Find TLS certificates that are about to expire, on live hosts and in PEM files, before they cause an outage.

**Status: working first version (v0.1.0).** Scanning hosts over the network, scanning PEM files and directories, the expiry report (date, issuer, days remaining), JSON output and exit codes all work today. Kubernetes scanning and notifications are not built yet.

## Install

Python 3.10 or newer. One dependency: [`cryptography`](https://cryptography.io/), used to parse certificates.

```bash
git clone https://github.com/narayana006/cert-expiry-watch
cd cert-expiry-watch
pip install .
```

## Quick start

The repository includes three sample certificates (public certificates only, issued for `.test` names):

```bash
cert-expiry-watch --pem examples/certs
```

```text
STATUS   DAYS  EXPIRES (UTC)     SUBJECT              ISSUER               SOURCE
EXPIRED  -985  2024-03-01 00:00  legacy.example.test  Example Internal CA  examples/certs/legacy.pem
OK         44  2026-12-25 00:00  api.example.test     Example Internal CA  examples/certs/api.pem
OK       3338  2036-01-01 00:00  shop.example.test    Example Internal CA  examples/certs/shop.pem

3 checked: 2 ok, 0 expiring within 21 days, 1 expired, 0 could not be checked
```

The command exits with status `1` because one certificate has expired. The output above was captured on 2026-11-10; the `DAYS` column counts from the moment you run it, so your numbers will be lower, and `api.example.test` turns `EXPIRING` and then `EXPIRED` as 2026-12-25 approaches.

Widen the warning window and the 44-day certificate is flagged too:

```bash
cert-expiry-watch --pem examples/certs/shop.pem --pem examples/certs/api.pem --warn-days 60
```

```text
STATUS    DAYS  EXPIRES (UTC)     SUBJECT            ISSUER               SOURCE
EXPIRING    44  2026-12-25 00:00  api.example.test   Example Internal CA  examples/certs/api.pem
OK        3338  2036-01-01 00:00  shop.example.test  Example Internal CA  examples/certs/shop.pem

2 checked: 1 ok, 1 expiring within 60 days, 0 expired, 0 could not be checked
```

To check live endpoints, list them in a file (see [`examples/hosts.txt`](examples/hosts.txt)) or name them directly:

```bash
cert-expiry-watch --hosts examples/hosts.txt --warn-days 21
cert-expiry-watch example.com internal.example.net:8443
```

## Usage

```text
cert-expiry-watch [HOST[:PORT] ...] [--hosts FILE] [--pem PATH]
                  [--warn-days N] [--timeout SECONDS] [--json]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `HOST[:PORT]` | port 443 | Endpoints to connect to. Also accepts `[ipv6]:port` and `https://` URLs. |
| `--hosts FILE` | | File with one endpoint per line; blank lines and `#` comments are ignored. Repeatable. |
| `--pem PATH` | | A PEM file, or a directory whose `.pem`, `.crt` and `.cer` files are checked (not recursive). Repeatable. |
| `--warn-days N` | 21 | Flag certificates with fewer than N days left. `0` flags only expired ones. |
| `--timeout SECONDS` | 5 | Connection and handshake timeout per host. |
| `--json` | off | Machine-readable output. |

Hosts, host files and PEM paths can be combined freely in one run. Hosts are checked in parallel. Rows are sorted with the most urgent first: errors, then by days remaining.

### Statuses

| Status | Meaning |
| --- | --- |
| `OK` | At least `--warn-days` days remain. |
| `EXPIRING` | Still valid, but fewer than `--warn-days` days remain. |
| `EXPIRED` | The expiry time has passed. `DAYS` is negative. |
| `ERROR` | The certificate could not be read (DNS failure, connection refused, timeout, unreadable file, no certificate in file). The reason is shown in the row. |

`DAYS` is rounded down: a certificate with 20 days and 23 hours left shows `20`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every certificate was read and none is inside the warning window. |
| `1` | At least one certificate is expired or expiring. |
| `2` | Nothing is expired or expiring, but at least one check failed. Also used for invalid arguments. |

That makes it usable directly in cron or CI:

```bash
cert-expiry-watch --hosts hosts.txt --warn-days 14 || echo "certificates need attention"
```

### JSON

```bash
cert-expiry-watch --pem examples/certs/api.pem --json
```

```json
{
  "checked_at": "2026-11-10T05:15:28Z",
  "warn_days": 21,
  "summary": {
    "ok": 1,
    "expiring": 0,
    "expired": 0,
    "error": 0
  },
  "results": [
    {
      "source": "examples/certs/api.pem",
      "kind": "file",
      "status": "ok",
      "subject": "api.example.test",
      "issuer": "Example Internal CA",
      "not_after": "2026-12-25T00:00:00Z",
      "days_remaining": 44,
      "san": [
        "api.example.test"
      ],
      "error": null
    }
  ]
}
```

`status` is one of `ok`, `expiring`, `expired`, `error`; `kind` is `host` or `file`. For errors the certificate fields are `null` and `error` holds the reason.

### How hosts are checked

The tool opens a TCP connection, completes a TLS handshake with SNI set to the host name, reads the leaf certificate the server presents and disconnects. Certificate verification is deliberately off, so that expired, self-signed and privately issued certificates can still be read and reported. This means the tool tells you *when* a certificate expires, not whether clients will trust it.

### PEM files

Every `CERTIFICATE` block in a file is checked, so a chain file produces one row per certificate (`chain.pem#1`, `chain.pem#2`, ...). Private keys in the same file are ignored and never parsed.

## Features

- [x] Scans a list of hostnames over the network
- [x] Scans PEM certificate files and directories on disk
- [ ] Scans Kubernetes TLS secrets and ingress resources (`--kube`)
- [x] Reports expiry date, issuer and days remaining
- [x] Exit code and JSON output for use in CI or cron
- [ ] Slack or webhook notification for certificates inside a warning window

## Limitations

- For hosts, only the leaf certificate is examined. An intermediate that expires sooner is not noticed unless you check the chain as a PEM file.
- No trust, hostname or revocation checks. A certificate for the wrong name with a year left is reported as `OK`.
- Direct TLS only. STARTTLS protocols (SMTP, IMAP, PostgreSQL) and connections through an HTTP proxy are not supported.
- PEM only; DER files, PKCS#12 bundles and Java keystores are not read.
- A certificate whose validity period has not started yet is not flagged.
- The `--kube` flag from the original design does not exist yet. Until it does, you can export a secret and check it as a file: `kubectl get secret my-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > my-tls.pem`.

## Contributing

Bug reports and pull requests are welcome. The test suite generates its own certificates and runs TLS servers on `127.0.0.1`; it never contacts external hosts.

```bash
pip install -e ".[dev]"
pytest
```

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
