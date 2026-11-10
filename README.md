# cert-expiry-watch

Find TLS certificates that are about to expire across domains, Kubernetes secrets and cloud load balancers.

> **Project status: planning. There is no working code in this repository yet.**
> This README describes what the project will do. Nothing below can be installed or run today.
> Features are ticked off in the checklist as they are built.

## What it is

A command-line tool.

**The problem it solves:** Expired certificates remain one of the most common and most avoidable causes of outages.

## Who it is for

Anyone responsible for keeping TLS certificates valid.

## How it will work

1. You give the tool a list of hostnames, a Kubernetes context, or both.
2. It reads each certificate and works out how many days remain.
3. It prints a report, returns a failing exit code if anything is inside your warning window and can send a notification.

## Planned features

Unticked items are not built yet.

- [ ] Scans a list of hostnames over the network
- [ ] Scans Kubernetes TLS secrets and ingress resources
- [ ] Reports expiry date, issuer and days remaining
- [ ] Exit code and JSON output for use in CI or cron
- [ ] Slack or webhook notification for certificates inside a warning window

## Planned usage

This is the intended interface, shown so you can judge the design. **It does not work yet**, and names may change before the first release.

```bash
cert-expiry-watch --hosts hosts.txt --kube --warn-days 21
```

## Contributing

Feedback on the design is the most useful contribution right now. Open an issue to suggest a feature, question an approach or describe your use case. Code contributions are welcome once the first version lands.

## License

[MIT](LICENSE)
