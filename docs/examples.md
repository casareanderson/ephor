# ephor — worked examples

Copy-paste recipes. Every command is detect-only unless it says otherwise. Replace `AGENT`, `WEBHOOK` and
`BOX` with your own values.

## 1. First look — what are my agents doing right now?

```bash
sudo pipx install ephor
ephor agents
ephor agent scraper --perms        # one agent: destinations + blast radius (what it can read)
```

`--perms` is the part the egress tools skip: the user it runs as, Linux capabilities, passwordless sudo, and
which secret files it can actually read.

## 2. Run it on a timer (cron)

```cron
# every 2 minutes: sample, record, and exit non-zero if a known-bad destination was seen
*/2 * * * * root ephor watch --resolve
```

The non-zero exit drops straight into a CI step too:

```bash
ephor watch --resolve || echo "KNOWN-BAD destination seen" | mail -s "ephor" you@example.com
```

## 3. Real-time alerts to Discord / Slack

```bash
ephor watch --loop --interval 30 --webhook "https://discord.com/api/webhooks/…"
ephor watch --loop --interval 30 --webhook "https://hooks.slack.com/services/…"
```

## 4. Ship alerts to a SIEM or Grafana Loki

```bash
# Grafana Loki (push API)
ephor watch --loop --webhook "https://logs-prod.grafana.net/loki/api/v1/push" --webhook-format loki

# any SIEM that ingests JSON over HTTP (the default, no format flag)
ephor watch --loop --webhook "https://siem.example.com/hooks/ephor"
```

The default body is the full alert JSON (`ts, host, agent, client, dest, ip, port, bytes_recv, reason, cmd, …`).

## 5. Opt-in enforcement: block known-bad destinations

```bash
# needs root and nft; adds an inet filter ephor-block drop rule per bad address
ephor watch --loop --block
```

Off by default on purpose — ephor is detect-only, and this is the one flag that makes it *act*.

## 6. Catch every connection (and DNS name) with eBPF

```bash
ephor probe --check          # can it run here?
ephor watch --loop --ebpf    # every exec, DNS lookup and connection as it happens
```

## 7. No eBPF? A local DNS forwarder ties names to processes

```bash
ephor dns-proxy --listen 127.0.0.1:5353 --webhook "https://discord.com/api/webhooks/…"
# point the box's resolver at 127.0.0.1:5353, then:
ephor dns --flagged          # names that a check flagged
```

## 8. Manage the learned baseline

```bash
ephor baseline export        # dump (agent, dest, port) of everything seen
ephor baseline reset         # clear history so the box re-learns from scratch
```

## 9. Query the history directly

```bash
ephor query --schema
ephor query "SELECT agent, dest, port, bytes_recv FROM conns WHERE bad=1 ORDER BY last_seen DESC"
```

## 10. Run as a systemd service

```ini
[Unit]
Description=ephor agent activity monitor

[Service]
ExecStart=/usr/local/bin/ephor watch --loop --interval 30 --webhook "https://discord.com/api/webhooks/…"
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Drop it in `/etc/systemd/system/ephor.service`, then `systemctl enable --now ephor`.
