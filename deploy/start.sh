#!/usr/bin/env bash
set -euo pipefail

# =====================================================================
# Threat Intelligence Platform — Production Launcher
#
# Usage:
#   ./deploy/start.sh install   — one-time setup (systemd + nginx)
#   ./deploy/start.sh start     — start the service
#   ./deploy/start.sh stop      — stop the service
#   ./deploy/start.sh restart   — restart
#   ./deploy/start.sh status    — show status
#   ./deploy/start.sh logs      — tail logs
#   ./deploy/start.sh harden    — enable basic auth + IP whitelist prompt
# =====================================================================

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_NAME="threat-intel"

# ------------------------------------------------------------------
install() {
    echo "[+] Installing Threat Intelligence Platform..."

    # 1. System packages
    apt-get update -qq
    apt-get install -y -qq nginx tor python3 python3-pip apache2-utils > /dev/null

    # 2. Python deps
    pip3 install -r "$APP_DIR/requirements.txt" --break-system-packages -q

    # 3. .env
    if [ ! -f "$APP_DIR/.env" ]; then
        cp "$APP_DIR/.env.example" "$APP_DIR/.env"
        echo "[!] Created .env — edit it now: $APP_DIR/.env"
    fi

    # 4. Log dir
    mkdir -p /var/log/threat-intel
    chown www-data:www-data /var/log/threat-intel

    # 5. systemd
    cp "$APP_DIR/deploy/threat-intel.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"

    # 6. nginx
    cp "$APP_DIR/deploy/nginx-threat-intel.conf" /etc/nginx/sites-available/threat-intel
    ln -sf /etc/nginx/sites-available/threat-intel /etc/nginx/sites-enabled/threat-intel
    rm -f /etc/nginx/sites-enabled/default

    nginx -t && systemctl reload nginx

    echo ""
    echo "[+] Installation complete!"
    echo ""
    echo "    Start:   systemctl start $SERVICE_NAME"
    echo "    Status:  systemctl status $SERVICE_NAME"
    echo "    Logs:    journalctl -u $SERVICE_NAME -f"
    echo ""
    echo "    Dashboard: http://$(hostname -I | awk '{print $1}')"
    echo ""
    echo "    Next: edit $APP_DIR/.env with your secrets"
    echo "          then run: systemctl start $SERVICE_NAME"
}

# ------------------------------------------------------------------
harden() {
    echo "=== Security Hardening ==="
    echo ""

    # Basic auth
    read -r -p "Enable basic auth password on the dashboard? [y/N] " yn
    if [[ "$yn" =~ ^[Yy] ]]; then
        read -r -p "Username: " htuser
        htpasswd -c /etc/nginx/.htpasswd "$htuser"
        sed -i '/location \/ {/a\        auth_basic "Threat Intel Platform";\n        auth_basic_user_file /etc/nginx/.htpasswd;' \
            /etc/nginx/sites-available/threat-intel
        echo "[+] Basic auth enabled"
    fi

    # IP whitelist
    read -r -p "Restrict to a single IP? [y/N] " yn
    if [[ "$yn" =~ ^[Yy] ]]; then
        read -r -p "Your IP address: " myip
        sed -i "/listen 80;/a\    allow $myip;\n    deny all;" \
            /etc/nginx/sites-available/threat-intel
        echo "[+] IP whitelist set to $myip"
    fi

    nginx -t && systemctl reload nginx
    echo "[+] Hardening applied."
}

# ------------------------------------------------------------------
case "${1:-}" in
    install)  install ;;
    start)    systemctl start "$SERVICE_NAME" && echo "[+] Started" ;;
    stop)     systemctl stop "$SERVICE_NAME" && echo "[+] Stopped" ;;
    restart)  systemctl restart "$SERVICE_NAME" && echo "[+] Restarted" ;;
    status)   systemctl status "$SERVICE_NAME" ;;
    logs)     journalctl -u "$SERVICE_NAME" -f ;;
    harden)   harden ;;
    *)
        echo "Usage: $0 {install|start|stop|restart|status|logs|harden}"
        exit 1
        ;;
esac
