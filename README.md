# mailfrom-milter

Postfix **milter** written in Go that enforces alignment between the SMTP envelope sender (`MAIL FROM` / envelope-from) and the `From:` message header (mime-from).

Licensed under **GPLv3 or SecondDNS Commercial License** — see [LICENSE](LICENSE) and [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL).

---

## The problem

When a mail server handles multiple domains, an authenticated user can set `MAIL FROM` to their own domain (satisfying SPF) but forge the `From:` header with any domain hosted on the same server. The DKIM signer picks up the `From:` domain and signs the message with that domain's key — producing a valid DKIM signature for a domain the sender does not own.

**This milter rejects such messages before DKIM signing occurs.**

Only authenticated SMTP sessions are checked. Unauthenticated connections (inbound MX delivery, relay) pass through without inspection.

---

## Actions

Configured via the `ACTION` environment variable or Helm `action` value.

| Action | Description |
|:---|:---|
| `reject` | Reject the message with SMTP 5xx. Reason code: **MFA001** |
| `discard` | Silently discard the message (sender gets no error) |
| `quarantine_header` | Accept the message, add `X-MF-Quarantine: yes` header |
| `dunno` | Accept the message, log the mismatch only |

Default: `reject`.

---

## Headers added

For every **authenticated** SMTP session, regardless of check outcome:

| Header | Value |
|:---|:---|
| `X-MF-Envelope-From` | Envelope sender address from `MAIL FROM` |

When action is `quarantine_header` and domains mismatch:

| Header | Value |
|:---|:---|
| `X-MF-Quarantine` | `yes` |

---

## Postfix configuration

Add the milter to `smtpd_milters` in `/etc/postfix/main.cf`:

```
smtpd_milters = inet:mailfrom.mail.svc.cluster.local:10031
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen} {auth_type}
milter_default_action = accept
```

`{auth_authen}` must be included in `milter_mail_macros` — it is present in the Postfix default value but verify it is not stripped in your configuration.

---

## Environment variables

| Variable | Default | Description |
|:---|:---|:---|
| `LISTEN_ADDR` | `0.0.0.0:10031` | TCP address the milter listens on |
| `ACTION` | `reject` | Action on mismatch: `reject`, `discard`, `quarantine_header`, `dunno` |
| `LOG_LEVEL` | — | Set to `debug` for verbose per-message logging |

---

## Logging

All logs are JSON via `log/slog`. Example entries:

```json
{"time":"...","level":"INFO","msg":"starting mailfrom-milter","listen":"0.0.0.0:10031","action":"reject"}
{"time":"...","level":"WARN","msg":"domain mismatch detected","envelope_domain":"attacker.com","from_domain":"victim.com","envelope_from":"user@attacker.com","from_header":"CEO <ceo@victim.com>","auth_user":"user@attacker.com","client_addr":"10.0.0.5","action":"reject"}
{"time":"...","level":"INFO","msg":"accepted","action":"accept","envelope_domain":"example.com","from_domain":"example.com","auth_user":"user@example.com","client_addr":"10.0.0.5"}
```

Enable debug logging (`LOG_LEVEL=debug`) to see every connection, MAIL FROM, and captured From: header.

---

## Stack

- Go 1.26
- `github.com/emersion/go-milter` v0.4.1
- Alpine 3.21 runtime image

---

## Directory layout

```
app/go/
|-  main.go          main binary
|-  Dockerfile       multi-stage builder -> alpine:3.21
|-  go.mod
\-  go.sum
helm/
|-  Chart.yaml
|-  values.yaml
\-  templates/
    |-  deployment.yaml
    \-  service.yaml
helm_values/
\-  values-micro-seconddns.yaml
argocd-app.yaml
.github/workflows/ci.yaml
```

---

## Deploy

### Kubernetes (ArgoCD)

```sh
kubectl apply -f argocd-app.yaml
```

ArgoCD syncs from the `helm/` directory using `helm_values/values-micro-seconddns.yaml`.

### Local build

```sh
docker build -t mailfrom:dev app/go/
docker run --rm -p 10031:10031 \
  -e ACTION=dunno \
  -e LOG_LEVEL=debug \
  mailfrom:dev
```

---

## CI

Push to `main` triggers GitHub Actions: builds `ghcr.io/0kaba0/mailfrom:<sha>` + `latest` for `linux/amd64`, then auto-commits the new tag into `helm_values/values-micro-seconddns.yaml`.
