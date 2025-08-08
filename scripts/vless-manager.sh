#!/usr/bin/env bash

set -euo pipefail

# VLESS (WebSocket + TLS) manager for Ubuntu with Xray + Nginx (CDN friendly)
# Features:
# - One-key install of dependencies, Xray, and Nginx
# - Domain verification (DNS A record -> server IP) prompt
# - Let's Encrypt TLS via certbot (Nginx plugin)
# - VLESS WS behind Nginx (works with Cloudflare CDN)
# - Client management: add, list, delete users
# - Live connection monitor (via Xray access logs)
# - Port/domain management, certificate reissue
# - Exposes ready-to-import VLESS links for clients (HTTP Injector compatible)

# Global constants
XRAY_BIN="/usr/local/bin/xray"
XRAY_SERVICE="xray"
XRAY_DIR="/usr/local/etc/xray"
XRAY_CONFIG="${XRAY_DIR}/config.json"
XRAY_ACCESS_LOG="/var/log/xray/access.log"
XRAY_ERROR_LOG="/var/log/xray/error.log"

NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"
NGINX_SITE_NAME="vless"
NGINX_SITE_FILE="${NGINX_AVAILABLE}/${NGINX_SITE_NAME}.conf"

ENV_FILE="/etc/vless-manager.env"

# Defaults (can be changed later via menu)
DEFAULT_TLS_PORT="443"
DEFAULT_XRAY_WS_PORT="10000"
DEFAULT_WS_PATH="/vlessws-$(tr -dc a-z0-9 </dev/urandom | head -c 8)"

# Color helpers
bold() { echo -e "\033[1m$*\033[0m"; }
green() { echo -e "\033[32m$*\033[0m"; }
red() { echo -e "\033[31m$*\033[0m"; }
yellow() { echo -e "\033[33m$*\033[0m"; }

require_root() {
  if [[ $(id -u) -ne 0 ]]; then
    red "This script must be run as root. Use: sudo $0"
    exit 1
  fi
}

require_ubuntu() {
  if ! command -v lsb_release >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y lsb-release
  fi
  local distro
  distro=$(lsb_release -is 2>/dev/null || echo "")
  if [[ "${distro}" != "Ubuntu" ]]; then
    yellow "Warning: This script is intended for Ubuntu. Continuing anyway."
  fi
}

ensure_cmd() {
  local cmd="$1"
  local pkg="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
  fi
}

get_public_ipv4() {
  # Try cloud service; fallback to local discovery
  curl -4 -s https://ifconfig.co || curl -4 -s https://api.ipify.org || hostname -I | awk '{print $1}'
}

resolve_ipv4() {
  local domain="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +short A "$domain" | head -n1
  else
    getent ahostsv4 "$domain" | awk '{print $1}' | head -n1
  fi
}

write_env() {
  cat >"${ENV_FILE}" <<EOF
DOMAIN="${DOMAIN}"
TLS_PORT="${TLS_PORT}"
XRAY_WS_PORT="${XRAY_WS_PORT}"
WS_PATH="${WS_PATH}"
CONTACT_EMAIL="${CONTACT_EMAIL}"
EOF
}

load_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
  else
    DOMAIN=""
    TLS_PORT="${DEFAULT_TLS_PORT}"
    XRAY_WS_PORT="${DEFAULT_XRAY_WS_PORT}"
    WS_PATH="${DEFAULT_WS_PATH}"
    CONTACT_EMAIL=""
  fi
}

pause() {
  read -r -p "Press Enter to continue..." _
}

prompt_domain_and_verify() {
  echo
  echo "Enter your domain (must point to this server's public IP)."
  read -r -p "Domain: " DOMAIN
  if [[ -z "${DOMAIN}" ]]; then
    red "Domain cannot be empty."
    exit 1
  fi
  local server_ip dns_ip
  server_ip=$(get_public_ipv4)
  dns_ip=$(resolve_ipv4 "${DOMAIN}")
  echo "Server public IPv4: $(bold "${server_ip}")"
  echo "${DOMAIN} resolves to: $(bold "${dns_ip}")"
  if [[ -z "${dns_ip}" ]]; then
    yellow "Could not resolve ${DOMAIN}. Ensure DNS A record exists."
  fi
  if [[ -n "${server_ip}" && -n "${dns_ip}" && "${server_ip}" != "${dns_ip}" ]]; then
    yellow "DNS for ${DOMAIN} does not match this server IP."
  fi
  read -r -p "Is the DNS configured correctly and propagated? (y/N): " ok
  if [[ "${ok}" != "y" && "${ok}" != "Y" ]]; then
    red "Aborting. Fix DNS and run again."
    exit 1
  fi
}

prompt_contact_email() {
  echo
  read -r -p "Contact email for Let's Encrypt (used for expiry notices): " CONTACT_EMAIL || true
  CONTACT_EMAIL=${CONTACT_EMAIL:-admin@${DOMAIN}}
}

install_dependencies() {
  echo
  green "Installing dependencies..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget jq tar unzip uuid-runtime \
    nginx certbot python3-certbot-nginx \
    socat net-tools iproute2
  ensure_cmd dig dnsutils
}

install_xray() {
  echo
  green "Installing Xray (core)..."
  bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
  mkdir -p "${XRAY_DIR}"
}

ensure_nginx_started() {
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl start nginx || true
}

configure_firewall() {
  # If UFW is enabled, allow HTTP and TLS port
  if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -qi active; then
      ufw allow 80/tcp || true
      ufw allow "${TLS_PORT}"/tcp || true
    fi
  fi
}

issue_certificate() {
  echo
  green "Issuing Let's Encrypt certificate via certbot (Nginx plugin)..."

  # Ensure a minimal server block for HTTP-01 challenge
  cat >"${NGINX_SITE_FILE}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    location / {
        return 200 'ok';
        add_header Content-Type text/plain;
    }
}
EOF
  ln -sf "${NGINX_SITE_FILE}" "${NGINX_ENABLED}/${NGINX_SITE_NAME}.conf"
  nginx -t
  systemctl reload nginx

  # Request/renew certificate
  certbot --nginx -d "${DOMAIN}" \
    --non-interactive --agree-tos -m "${CONTACT_EMAIL}" --no-eff-email || {
      red "Certbot failed. Ensure port 80 is reachable and Cloudflare proxy is disabled during issuance."
      exit 1
    }
}

write_nginx_proxy_conf() {
  echo
  green "Configuring Nginx reverse proxy (WS + TLS on port ${TLS_PORT})..."
  local ssl_dir="/etc/letsencrypt/live/${DOMAIN}"
  if [[ ! -d "${ssl_dir}" ]]; then
    red "Certificate directory ${ssl_dir} not found."
    exit 1
  fi

  cat >"${NGINX_SITE_FILE}" <<EOF
server {
    listen ${TLS_PORT} ssl http2;
    listen [::]:${TLS_PORT} ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${ssl_dir}/fullchain.pem;
    ssl_certificate_key ${ssl_dir}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Default site root
    root /var/www/html;
    index index.html;

    # WebSocket reverse proxy to Xray
    location ${WS_PATH} {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${XRAY_WS_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 86400;
    }

    # Basic health page
    location /health {
        return 200 'healthy';
        add_header Content-Type text/plain;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / {
        return 301 https://\$host:${TLS_PORT}\$request_uri;
    }
}
EOF

  ln -sf "${NGINX_SITE_FILE}" "${NGINX_ENABLED}/${NGINX_SITE_NAME}.conf"
  nginx -t
  systemctl reload nginx
  configure_firewall
}

write_xray_config() {
  echo
  green "Writing Xray config (VLESS WS)..."
  mkdir -p "${XRAY_DIR}"
  mkdir -p "$(dirname "${XRAY_ACCESS_LOG}")"

  cat >"${XRAY_CONFIG}" <<EOF
{
  "log": {
    "access": "${XRAY_ACCESS_LOG}",
    "error": "${XRAY_ERROR_LOG}",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${XRAY_WS_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${WS_PATH}",
          "headers": { "Host": "${DOMAIN}" }
        }
      },
      "tag": "vless-ws"
    },
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "tag": "api"
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["api"], "outboundTag": "api" }
    ]
  },
  "api": {
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "policy": {
    "levels": {
      "0": { "statsUserUplink": true, "statsUserDownlink": true }
    },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  }
}
EOF

  systemctl enable ${XRAY_SERVICE} >/dev/null 2>&1 || true
  systemctl restart ${XRAY_SERVICE}
}

show_status() {
  echo
  green "Current settings:"
  echo "  Domain:        $(bold "${DOMAIN:-<unset>}")"
  echo "  TLS Port:      $(bold "${TLS_PORT}")"
  echo "  WS Path:       $(bold "${WS_PATH}")"
  echo "  Xray WS Port:  $(bold "${XRAY_WS_PORT}") (127.0.0.1 only)"
  echo "  Cert email:    $(bold "${CONTACT_EMAIL:-<unset>}")"
  echo
  systemctl -q is-active ${XRAY_SERVICE} && echo "Xray: $(green active)" || echo "Xray: $(red inactive)"
  systemctl -q is-active nginx && echo "Nginx: $(green active)" || echo "Nginx: $(red inactive)"
}

vless_link_for() {
  local uuid="$1"
  local name="$2"
  local host="$3"
  local tls_port="$4"
  local ws_path="$5"
  printf "vless://%s@%s:%s?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%s#%s\n" \
    "$uuid" "$host" "$tls_port" "$host" "$host" "$ws_path" "$name"
}

add_client() {
  echo
  read -r -p "New client name (no spaces): " name
  if [[ -z "$name" ]]; then
    red "Client name cannot be empty."
    return 1
  fi
  if ! [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
    red "Invalid name. Use letters, numbers, '.', '_', or '-'."
    return 1
  fi
  local uuid
  if command -v uuidgen >/dev/null 2>&1; then
    uuid=$(uuidgen)
  else
    uuid=$(cat /proc/sys/kernel/random/uuid)
  fi

  # Add client to Xray config using jq
  tmpcfg=$(mktemp)
  jq --arg id "$uuid" --arg email "$name" \
     '.inbounds |= (map(if .protocol == "vless" then (.settings.clients += [{"id": $id, "email": $email}]) else . end))' \
     "${XRAY_CONFIG}" >"${tmpcfg}"
  mv "${tmpcfg}" "${XRAY_CONFIG}"
  systemctl reload ${XRAY_SERVICE} || systemctl restart ${XRAY_SERVICE}

  echo
  green "Client added. Import link:"
  vless_link_for "$uuid" "$name" "$DOMAIN" "$TLS_PORT" "$WS_PATH"
}

list_clients() {
  echo
  green "Existing clients:"
  jq -r '.inbounds[] | select(.protocol=="vless") | .settings.clients[] | "- " + .email + " (" + .id + ")"' "${XRAY_CONFIG}" || true
}

delete_client() {
  echo
  read -r -p "Delete by (1) name or (2) UUID? [1/2]: " mode
  local key val
  if [[ "$mode" == "2" ]]; then
    key="id"; read -r -p "UUID: " val
  else
    key="email"; read -r -p "Name: " val
  fi
  tmpcfg=$(mktemp)
  jq --arg key "$key" --arg val "$val" \
     '(.inbounds[] | select(.protocol=="vless") | .settings.clients) |= map(select(.[$key] != $val))' \
     "${XRAY_CONFIG}" >"${tmpcfg}"
  mv "${tmpcfg}" "${XRAY_CONFIG}"
  systemctl reload ${XRAY_SERVICE} || systemctl restart ${XRAY_SERVICE}
  green "Client deleted (if existed)."
}

show_client_link() {
  echo
  read -r -p "Client name: " name
  local uuid
  uuid=$(jq -r --arg name "$name" '.inbounds[] | select(.protocol=="vless") | .settings.clients[] | select(.email==$name) | .id' "${XRAY_CONFIG}")
  if [[ -z "$uuid" || "$uuid" == "null" ]]; then
    red "Client not found."
    return 1
  fi
  vless_link_for "$uuid" "$name" "$DOMAIN" "$TLS_PORT" "$WS_PATH"
}

monitor_live() {
  echo
  green "Streaming live connections from ${XRAY_ACCESS_LOG} (Ctrl+C to stop)"
  echo "Showing accepted connections with client names (emails)."
  echo
  if [[ ! -f "${XRAY_ACCESS_LOG}" ]]; then
    red "Access log not found: ${XRAY_ACCESS_LOG}. Start some traffic first."
  fi
  tail -F "${XRAY_ACCESS_LOG}" | awk '/accepted/ {print strftime("%Y-%m-%d %H:%M:%S"), $0}'
}

change_domain() {
  prompt_domain_and_verify
  prompt_contact_email
  write_env
  issue_certificate
  write_nginx_proxy_conf
  # Update Host header in Xray config
  tmpcfg=$(mktemp)
  jq --arg host "$DOMAIN" '(.inbounds[] | select(.protocol=="vless") | .streamSettings.wsSettings.headers.Host) |= $host' \
    "${XRAY_CONFIG}" >"${tmpcfg}"
  mv "${tmpcfg}" "${XRAY_CONFIG}"
  systemctl reload nginx
  systemctl restart ${XRAY_SERVICE}
  green "Domain updated."
}

change_tls_port() {
  echo
  read -r -p "New TLS port (current ${TLS_PORT}): " newp
  if ! [[ "$newp" =~ ^[0-9]+$ ]]; then
    red "Invalid port."
    return 1
  fi
  TLS_PORT="$newp"
  write_env
  write_nginx_proxy_conf
  systemctl reload nginx
  green "TLS port updated to ${TLS_PORT}."
}

change_ws_path() {
  echo
  read -r -p "New WebSocket path (current ${WS_PATH}, must start with /): " newp
  if [[ -z "$newp" || "${newp:0:1}" != "/" ]]; then
    red "Invalid path."
    return 1
  fi
  WS_PATH="$newp"
  write_env
  # Update Nginx and Xray
  write_nginx_proxy_conf
  tmpcfg=$(mktemp)
  jq --arg path "$WS_PATH" '(.inbounds[] | select(.protocol=="vless") | .streamSettings.wsSettings.path) |= $path' \
    "${XRAY_CONFIG}" >"${tmpcfg}"
  mv "${tmpcfg}" "${XRAY_CONFIG}"
  systemctl reload nginx
  systemctl restart ${XRAY_SERVICE}
  green "WebSocket path updated to ${WS_PATH}."
}

change_internal_xray_port() {
  echo
  read -r -p "New internal Xray WS port (current ${XRAY_WS_PORT}): " newp
  if ! [[ "$newp" =~ ^[0-9]+$ ]]; then
    red "Invalid port."
    return 1
  fi
  XRAY_WS_PORT="$newp"
  write_env
  # Update Nginx and Xray
  write_nginx_proxy_conf
  tmpcfg=$(mktemp)
  jq --argjson port "$XRAY_WS_PORT" '(.inbounds[] | select(.protocol=="vless") | .port) |= $port' \
    "${XRAY_CONFIG}" >"${tmpcfg}"
  mv "${tmpcfg}" "${XRAY_CONFIG}"
  systemctl reload nginx
  systemctl restart ${XRAY_SERVICE}
  green "Internal Xray WS port updated to ${XRAY_WS_PORT}."
}

renew_certificate() {
  echo
  green "Renewing certificate for ${DOMAIN}..."
  certbot renew --force-renewal --no-random-sleep-on-renew
  systemctl reload nginx
  green "Certificate renewed."
}

install_all() {
  require_root
  require_ubuntu
  install_dependencies
  install_xray
  ensure_nginx_started
  prompt_domain_and_verify
  prompt_contact_email
  TLS_PORT="${TLS_PORT:-${DEFAULT_TLS_PORT}}"
  XRAY_WS_PORT="${XRAY_WS_PORT:-${DEFAULT_XRAY_WS_PORT}}"
  WS_PATH="${WS_PATH:-${DEFAULT_WS_PATH}}"
  write_env
  issue_certificate
  write_nginx_proxy_conf
  write_xray_config
  show_status
  green "Installation complete. Add a client from the menu to get a VLESS link."
}

menu() {
  load_env
  while true; do
    echo
    echo "$(bold "VLESS Manager - Xray + Nginx (CDN)")"
    echo "Domain: ${DOMAIN:-<unset>}  TLS:${TLS_PORT}  WS_PATH:${WS_PATH}  XRAY_WS_PORT:${XRAY_WS_PORT}"
    echo
    cat <<M
1) Install / Reinstall (Xray + Nginx + TLS)
2) Add client
3) List clients
4) Delete client
5) Show client VLESS link
6) Live connections monitor
7) Change domain (and reissue cert)
8) Change TLS port (Nginx)
9) Change WebSocket path
10) Change internal Xray WS port
11) Renew certificate
12) Show status
0) Exit
M
    read -r -p "Select an option: " opt
    case "$opt" in
      1) install_all ;;
      2) add_client ;;
      3) list_clients ;;
      4) delete_client ;;
      5) show_client_link ;;
      6) monitor_live ;;
      7) change_domain ;;
      8) change_tls_port ;;
      9) change_ws_path ;;
      10) change_internal_xray_port ;;
      11) renew_certificate ;;
      12) show_status ;;
      0) exit 0 ;;
      *) echo "Invalid option" ;;
    esac
  done
}

main() {
  if [[ ${1:-} == "--install" ]]; then
    install_all
  else
    menu
  fi
}

main "$@"

