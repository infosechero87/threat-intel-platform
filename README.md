# 🛡️ Cyber Threat Intelligence Platform

Real-time cyber threat intelligence dashboard with dark web search, Telegram channel monitoring, threat feed aggregation, and credential breach checking.

![Dashboard Screenshot](https://img.shields.io/badge/Platform-Web%20%2B%20GUI-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

| Module | Description |
|--------|-------------|
| **Dashboard** | Real-time WebSocket alerts, severity stats, live threat feed |
| **Dark Web Search** | Query 12 clearnet/darknet sources — exploit DBs, forums, paste sites, CVE database, ransomware trackers |
| **Telegram Monitor** | Track 11 pre-configured channels (ransomware groups, exploit traders, IOC sharing) with IOC auto-highlighting |
| **Threat Feeds** | Aggregated intel from CISA, FBI, Mandiant, CrowdStrike, NCSC, ENISA, Proofpoint, and more |
| **Credential Checker** | Check emails/passwords against breach databases via HIBP k-anonymity API + simulated breach DB |
| **Password Analyzer** | Entropy scoring, character set detection, common pattern detection |

## Quick Start

```bash
# Clone
git clone https://github.com/yourusername/threat-intel-platform.git
cd threat-intel-platform

# Install
pip install -r requirements.txt
# (add --break-system-packages on Debian/Ubuntu if needed)

# Copy config (optional)
cp .env.example .env

# Run web dashboard
python3 app.py
# → http://YOUR_SERVER_IP:5000

# Run credential checker GUI (requires X11/desktop)
python3 credential_checker_gui.py
```

## Vultr / Cloud Deployment

### Option 1: Quick (development server)

```bash
# On your Vultr VPS (Ubuntu/Debian)
apt update && apt install -y python3 python3-pip git
git clone https://github.com/yourusername/threat-intel-platform.git
cd threat-intel-platform
pip3 install -r requirements.txt --break-system-packages
python3 app.py
```

### Option 2: Production with systemd + Nginx

```bash
# Install systemd service
sudo cp deploy/threat-intel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threat-intel

# Reverse proxy with Nginx
sudo apt install -y nginx
sudo cp deploy/nginx-threat-intel.conf /etc/nginx/sites-available/threat-intel
sudo ln -s /etc/nginx/sites-available/threat-intel /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Enable HTTPS with certbot
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### Option 3: Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python3", "app.py"]
```

```bash
docker build -t threat-intel .
docker run -d -p 5000:5000 --name threat-intel threat-intel
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | auto-generated | Flask session secret |
| `FLASK_HOST` | `0.0.0.0` | Bind address |
| `FLASK_PORT` | `5000` | Listen port |
| `TELEGRAM_API_ID` | — | Telegram API ID (for live monitoring) |
| `TELEGRAM_API_HASH` | — | Telegram API hash |
| `TELEGRAM_PHONE` | — | Phone number for Telegram auth |
| `HIBP_API_KEY` | — | HaveIBeenPwned API key (enables full breach data) |
| `OTX_API_KEY` | — | AlienVault OTX API key |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Threat statistics (total, critical, high, medium, low) |
| `GET` | `/api/alerts` | Recent alert stream |
| `POST` | `/api/darkweb/search` | Search dark web sources `{query, sources}` |
| `POST` | `/api/telegram/search` | Search Telegram messages `{query, channel, limit}` |
| `GET` | `/api/telegram/channels` | List tracked Telegram channels |
| `POST` | `/api/telegram/channels` | Add a channel `{channel}` |
| `GET` | `/api/feeds` | Aggregated threat feeds `?category=&limit=` |
| `POST` | `/api/check-single` | Check single credential `{email, password}` |
| `POST` | `/api/check-credentials` | Bulk check `{credentials: [{email, password}]}` |
| `WS` | `/ws/alerts` | WebSocket real-time alert stream |

## Dark Web Sources

| Source | Type | Status |
|--------|------|--------|
| Exploit-DB | Exploit database | Clearnet |
| CVE Database (circl.lu) | Vulnerability DB | Clearnet API |
| AlienVault OTX | Threat pulses | Clearnet API |
| ThreatFox | IOC database | Simulated |
| URLhaus | Malware URLs | Simulated |
| MalwareBazaar | Malware samples | Simulated |
| Ransomware Tracker | Ransomware C2/IOCs | Simulated |
| Paste Sites | Leaked data/pastes | Simulated |
| XSS.is Forum | Hacker forum | Simulated |
| BreachForums | Data leak marketplace | Simulated |
| RaidForums | Forum archive | Simulated |
| DarkNet Markets | Darknet marketplace | Simulated |

> **Note:** Simulated sources contain realistic threat intelligence data modeled after real dark web activity. Connect actual APIs/Tor for live data.

## Telegram Channels Tracked

- **Ransomware:** LockBit, ALPHV/BlackCat, Cl0p, Play
- **Exploit Trading:** 0Day Trade Alerts, Exploit Forum Feed
- **Data Leaks:** LeakBase Official, Breach Alerts
- **IOC Sharing:** Threat Intel Feed, Malware IOC Feed
- **APT Reporting:** APT Threat Reports

## Project Structure

```
threat_intel_platform/
├── app.py                      # Flask web server
├── credential_checker_gui.py   # Standalone Tkinter GUI
├── requirements.txt
├── .env.example
├── .gitignore
├── start.sh
├── modules/
│   ├── darkweb_search.py       # Dark web search engine
│   ├── telegram_monitor.py     # Telegram channel monitor
│   ├── threat_feeds.py         # Feed aggregator
│   └── credential_checker.py   # Breach checker (HIBP)
├── templates/
│   ├── base.html               # Base layout (dark theme)
│   ├── dashboard.html          # Live dashboard
│   ├── darkweb.html            # Dark web search UI
│   ├── telegram.html           # Telegram monitor UI
│   ├── feeds.html              # Threat feed UI
│   └── credentials.html        # Credential checker UI
├── static/
│   ├── css/style.css           # Full dark theme
│   └── js/app.js               # Client utilities
└── deploy/
    ├── threat-intel.service    # systemd unit
    └── nginx-threat-intel.conf # Nginx reverse proxy config
```

## Security Considerations

- **Password checking uses k-anonymity** — only the first 5 characters of the SHA-1 hash are sent to HIBP
- Set a strong `SECRET_KEY` in `.env` for production
- Use HTTPS in production (Nginx reverse proxy + certbot)
- The web interface has no authentication — place it behind a VPN, IP whitelist, or add auth middleware for production use
- The Telegram module by default uses simulated data; connect a real Telethon session for live monitoring

## License

MIT — Use responsibly. This tool is designed for authorized security research and threat intelligence purposes only.
