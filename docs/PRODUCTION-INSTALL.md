# Production installation

```bash
sudo bash deploy/scripts/install.sh --prod --domain <name-or-ip> [TLS option]
```

## Choose how users reach the platform (TLS)

| | **1. Public domain — Let's Encrypt** | **2. Internal — private domain / IP** |
|---|---|---|
| Flag | `--tls letsencrypt --email you@corp.com` | `--tls internal` |
| Certificate | Free, browser-trusted, **auto-renews** | Self-signed (generated), **or your own CA's** |
| Needs | A **public DNS name** pointing at this server; ports **80 & 443 reachable from the internet** | Nothing external |
| Your CA cert | – | `--cert fullchain.pem --key privkey.pem` |

Run without `--tls` and the installer asks. With `--unattended` it defaults to *internal*.

```bash
# 1) public
sudo bash install.sh --prod --domain pentest.acme.com --email secops@acme.com --tls letsencrypt
# 2a) internal, self-signed (users must trust the generated certificate)
sudo bash install.sh --prod --domain 10.20.0.15 --tls internal
# 2b) internal, your own CA certificate (recommended — no browser warnings)
sudo bash install.sh --prod --domain pentest.corp.lan --tls internal --cert /etc/pki/pentest.crt --key /etc/pki/pentest.key
```

**Let's Encrypt:** the installer first does a *staging dry-run* (so a DNS/firewall mistake can't burn rate limits). If validation fails the platform still comes up on a temporary self-signed certificate; fix DNS/port 80, then run `sudo socis-cert-renew --issue`. Renewal is automatic (`socis-cert-renew.timer`, twice daily).

**Internal / self-signed:** distribute `<install-dir>/ssl/fullchain.pem` to client trust stores. Supplying `--cert/--key` from your internal CA avoids this. Provide the **full chain** (leaf + intermediates).

## Other options
`--admin-password <pw>` (≥12 chars; otherwise one is generated and shown **once**, also saved root-only in `<install-dir>/.admin-credentials`) · `--allow-private-targets` (permit scanning RFC1918 ranges; off by default — loopback and cloud-metadata are always blocked) · `--install-dir` · `--no-monitoring` · `--unattended`.

## Safe to re-run
Re-running the installer **reuses** the database password, encryption key, JWT secret, MCP token, admin password and existing certificate, so sessions, MFA and encrypted settings survive. A timestamped `.env.backup.*` (root-only) is kept.

## Check before you install, and after
```bash
bash deploy/scripts/prod-preflight.sh                       # validates prod files; installs nothing
COMPOSE_FILE=docker-compose.prod.yml bash deploy/scripts/verify.sh /opt/socis.io/SOCIS-AI-PT https://<domain>   # after install
```

## Troubleshooting
* **502 after recreating a container (dev only)** — the dev nginx pins container IPs at startup: `docker compose -f docker-compose.dev.yml restart nginx`. The production nginx re-resolves automatically and does not need this.
* **Let's Encrypt failed during install** — the platform is up on a temporary certificate. Fix DNS / open port 80, then `sudo socis-cert-renew --issue`.

## Behind a load balancer / reverse proxy
Rate limiting and audit logs use the client address nginx sees (`$remote_addr`). If another proxy sits in front of nginx, every user would appear as that proxy. Tell nginx to trust it and recover the real address — add to the `http {}` block of `deploy/nginx/nginx.prod.conf`:
```
set_real_ip_from  <load-balancer-IP-or-subnet>;
real_ip_header    X-Forwarded-For;
real_ip_recursive on;
```
Only list proxies you control; anything else could spoof client addresses.
