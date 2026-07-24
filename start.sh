#!/bin/bash
set -e
cd "$(dirname "$0")"

install_deps() {
    if ! python3 -c "import flask" 2>/dev/null; then
        echo "[*] Installing Python dependencies..."
        pip3 install flask flask-sock requests --break-system-packages -q 2>/dev/null || \
        pip3 install flask flask-sock requests -q
        echo "[+] Dependencies installed."
    fi
}

case "${1:-web}" in
    web)
        install_deps
        python3 app.py
        ;;
    gui)
        echo "[*] Launching Credential Checker GUI..."
        python3 credential_checker_gui.py
        ;;
    both)
        install_deps
        python3 app.py &
        WEB_PID=$!
        sleep 2
        echo "[*] Launching Credential Checker GUI..."
        python3 credential_checker_gui.py
        kill $WEB_PID 2>/dev/null || true
        ;;
    docker-build)
        docker build -t threat-intel .
        echo "[+] Image built: threat-intel"
        echo "    Run: docker run -d -p 5000:5000 --name threat-intel threat-intel"
        ;;
    *)
        echo "Usage: $0 {web|gui|both|docker-build}"
        echo "  web          - Start web dashboard (default)"
        echo "  gui          - Start credential checker GUI"
        echo "  both         - Start both web + GUI"
        echo "  docker-build - Build Docker image"
        ;;
esac
