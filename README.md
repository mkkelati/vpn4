## VLESS (WebSocket + TLS) Manager for Ubuntu

This repository provides a Bash-based manager that installs and configures Xray (VLESS over WebSocket + TLS) behind Nginx, suitable for Cloudflare CDN and compatible with HTTP Injector via standard VLESS import links.

### Quick install from GitHub (recommended)
Repo: `github.com/mkkelati/vpn4`

```bash
sudo bash -c 'curl -fsSL https://raw.githubusercontent.com/mkkelati/vpn4/main/scripts/vless-manager.sh -o /usr/local/sbin/vless-manager && chmod +x /usr/local/sbin/vless-manager && /usr/local/sbin/vless-manager'
```

- One-shot installer (runs install flow immediately; still interactive for domain prompts):

```bash
curl -fsSL https://raw.githubusercontent.com/mkkelati/vpn4/main/scripts/vless-manager.sh | sudo bash -s -- --install
```

### Upgrade to latest script
```bash
sudo bash -c 'curl -fsSL https://raw.githubusercontent.com/mkkelati/vpn4/main/scripts/vless-manager.sh -o /usr/local/sbin/vless-manager && chmod +x /usr/local/sbin/vless-manager'
```

### Features
- **One-key install**: Xray core, Nginx, Certbot (Let’s Encrypt TLS)
- **CDN ready**: Works via Cloudflare; proxied after certificate issuance
- **Client management**: Add, list, delete users; show ready-to-import VLESS links
- **Domain/port management**: Change domain, TLS port, WS path, internal Xray port
- **Live monitoring**: Tail Xray access logs to see active connections in real-time

### Requirements
- Ubuntu server (root or `sudo`)
- A domain with an A record pointing to the server’s IPv4
- Port 80 and chosen TLS port (default 443) open to the internet

### Cloudflare Notes
- During certificate issuance, ensure the domain’s orange-cloud proxy is DISABLED (DNS Only) so HTTP-01 validation can reach your server on port 80.
- After successful issuance, you can re-enable Cloudflare proxy.

### Install
1. Copy the script to your Ubuntu server (from Windows, you can use `scp` via PowerShell):
   ```powershell
scp -r C:\\Users\\<you>\\vpn4\\scripts\\vless-manager.sh ubuntu@<server-ip>:/tmp/
   ```
2. SSH to the server and run:
   ```bash
sudo mv /tmp/vless-manager.sh /usr/local/sbin/vless-manager
sudo chmod +x /usr/local/sbin/vless-manager
sudo vless-manager
   ```

### Usage
The menu provides:
- Install/Reinstall the full stack (Xray + Nginx + TLS)
- Add/List/Delete clients
- Show client’s VLESS link (import into HTTP Injector)
- Live connections monitor (tail access log)
- Change domain / TLS port / WS path / internal Xray port
- Renew certificate and show status

### Typical Flow
1. Choose “Install / Reinstall”. You’ll be asked to provide the domain (must resolve to server IP) and a contact email.
2. After installation, choose “Add client” and provide a username. The script prints a VLESS link like:
   ```
vless://<UUID>@your.domain:443?encryption=none&security=tls&sni=your.domain&type=ws&host=your.domain&path=/vlessws-xxxx#username
   ```
3. Copy the link and import into HTTP Injector (supports standard VLESS links).
4. Use “Live connections monitor” to watch accepted connections in real-time.

### Files Written
- Nginx site: `/etc/nginx/sites-available/vless.conf` (+ symlink in `sites-enabled`)
- Xray config: `/usr/local/etc/xray/config.json`
- Xray logs: `/var/log/xray/access.log`, `/var/log/xray/error.log`
- Manager env: `/etc/vless-manager.env`

### Uninstall (manual)
- Stop and remove Nginx site: `sudo rm -f /etc/nginx/sites-enabled/vless.conf /etc/nginx/sites-available/vless.conf && sudo systemctl reload nginx`
- Remove Xray using the upstream installer if needed.

### Troubleshooting
- Certbot failure: Ensure port 80 is reachable from the internet and Cloudflare proxy is disabled during issuance.
- No live logs: Generate traffic first and ensure Xray service is active (`systemctl status xray`).

