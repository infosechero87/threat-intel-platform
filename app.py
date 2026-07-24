#!/usr/bin/env python3
"""Cyber Threat Intelligence Platform - Main Application"""
import os
import json
import threading
import time
import queue
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from flask_sock import Sock

from modules.darkweb_search import DarkWebSearcher
from modules.telegram_monitor import TelegramMonitor
from modules.threat_feeds import ThreatFeedAggregator
from modules.credential_checker import check_credentials_bulk, check_single_credential
from modules.tor_config import TOR_AVAILABLE, TOR_ENABLED, TOR_PROXY


def _load_env():
    """Load .env file if present (no external dependency)."""
    env_path = Path(__file__).resolve().parent / '.env'
    if env_path.is_file():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, val = line.partition('=')
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


_load_env()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
sock = Sock(app)

# Global state
alert_queue = queue.Queue()
active_alerts = []
threat_stats = {
    'total_threats': 0,
    'critical': 0,
    'high': 0,
    'medium': 0,
    'low': 0,
    'last_updated': None
}

searcher = DarkWebSearcher()
telegram = TelegramMonitor()
feed_agg = ThreatFeedAggregator()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def dashboard():
    """Main threat intelligence dashboard."""
    return render_template('dashboard.html', stats=threat_stats)


@app.route('/darkweb')
def darkweb_search():
    """Dark web forum search page."""
    return render_template('darkweb.html')


@app.route('/api/darkweb/search', methods=['POST'])
def api_darkweb_search():
    """Search dark web / hacker forums for threat intel."""
    data = request.get_json()
    query = data.get('query', '')
    sources = data.get('sources', ['all'])
    results = searcher.search(query, sources)
    return jsonify({'results': results, 'query': query, 'count': len(results)})


@app.route('/telegram')
def telegram_page():
    """Telegram channel monitoring page."""
    channels = telegram.get_tracked_channels()
    return render_template('telegram.html', channels=channels)


@app.route('/api/telegram/search', methods=['POST'])
def api_telegram_search():
    """Search tracked Telegram channels."""
    data = request.get_json()
    query = data.get('query', '')
    channel = data.get('channel', None)
    limit = data.get('limit', 100)
    results = telegram.search_messages(query, channel, limit)
    return jsonify({'results': results, 'count': len(results)})


@app.route('/api/telegram/channels', methods=['GET'])
def api_telegram_channels():
    """Get list of tracked Telegram channels."""
    return jsonify({'channels': telegram.get_tracked_channels()})


@app.route('/api/telegram/channels', methods=['POST'])
def api_add_channel():
    """Add a Telegram channel to tracking."""
    data = request.get_json()
    channel = data.get('channel', '')
    if channel:
        telegram.add_channel(channel)
        return jsonify({'status': 'added', 'channel': channel})
    return jsonify({'status': 'error', 'message': 'No channel provided'}), 400


@app.route('/feeds')
def threat_feeds():
    """Real-time threat feed aggregation page."""
    return render_template('feeds.html')


@app.route('/api/feeds', methods=['GET'])
def api_feeds():
    """Get aggregated threat feed data."""
    category = request.args.get('category', 'all')
    limit = int(request.args.get('limit', 50))
    feeds = feed_agg.get_feeds(category, limit)
    return jsonify({'feeds': feeds, 'count': len(feeds), 'categories': feed_agg.get_categories()})


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get current threat statistics."""
    threat_stats['last_updated'] = datetime.now(timezone.utc).isoformat()
    return jsonify(threat_stats)


@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get recent alerts stream."""
    alerts = list(active_alerts[-50:])
    return jsonify({'alerts': alerts, 'count': len(alerts)})


@app.route('/credentials')
def credentials_page():
    """Credential checking tool page."""
    return render_template('credentials.html')


@app.route('/api/check-credentials', methods=['POST'])
def api_check_credentials():
    """Check a list of credentials against breach databases."""
    data = request.get_json()
    credentials = data.get('credentials', [])
    if not credentials:
        return jsonify({'status': 'error', 'message': 'No credentials provided'}), 400
    
    results = check_credentials_bulk(credentials)
    compromised = sum(1 for r in results if r.get('compromised'))
    return jsonify({
        'results': results,
        'total': len(results),
        'compromised': compromised,
        'safe': len(results) - compromised
    })


@app.route('/api/check-single', methods=['POST'])
def api_check_single():
    """Check a single email/password pair."""
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    if not email:
        return jsonify({'status': 'error', 'message': 'Email required'}), 400
    
    result = check_single_credential(email, password)
    return jsonify(result)


@app.route('/api/tor/status', methods=['GET'])
def api_tor_status():
    """Get Tor configuration status."""
    return jsonify({
        'tor_enabled': TOR_ENABLED,
        'tor_available': TOR_AVAILABLE,
        'tor_proxy': TOR_PROXY,
        'darkweb_sources': {
            'cve_api': True,
            'otx_api': True,
            'urlhaus_api': True,
            'ransomware_live_api': True,
            'rss_feeds': True,
            'darknetlive': TOR_AVAILABLE,
            'dread_forum': TOR_AVAILABLE,
            'simulated_fallback': True
        }
    })


# ---------------------------------------------------------------------------
# WebSocket for real-time alerts
# ---------------------------------------------------------------------------

@sock.route('/ws/alerts')
def ws_alerts(ws):
    """Push real-time threat alerts to connected clients."""
    while True:
        try:
            if not alert_queue.empty():
                alert = alert_queue.get_nowait()
                ws.send(json.dumps(alert))
            else:
                ws.send(json.dumps({'type': 'heartbeat', 'ts': datetime.now(timezone.utc).isoformat()}))
            time.sleep(2)
        except Exception:
            break


# ---------------------------------------------------------------------------
# Background threat monitoring
# ---------------------------------------------------------------------------

def background_monitor():
    """Continuously poll threat sources and push alerts."""
    while True:
        try:
            # Pull from threat feeds
            for feed in feed_agg.poll_new():
                alert_queue.put({
                    'type': 'threat',
                    'source': feed.get('source', 'unknown'),
                    'title': feed.get('title', ''),
                    'severity': feed.get('severity', 'medium'),
                    'url': feed.get('url', ''),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })
                active_alerts.append(feed)
                threat_stats['total_threats'] += 1
                threat_stats[feed.get('severity', 'medium')] += 1

            # Trim old alerts
            while len(active_alerts) > 500:
                active_alerts.pop(0)

            # Telegram monitoring
            new_msgs = telegram.poll_new_messages()
            for msg in new_msgs:
                if any(kw in msg.get('text', '').lower() for kw in
                       ['exploit', 'breach', 'leak', 'ransomware', '0day', 'vuln', 'cve']):
                    alert_queue.put({
                        'type': 'telegram',
                        'channel': msg.get('channel', ''),
                        'text': msg.get('text', '')[:300],
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })

            time.sleep(30)
        except Exception as e:
            print(f"[Monitor] Error: {e}")
            time.sleep(60)


# Start background thread
monitor_thread = threading.Thread(target=background_monitor, daemon=True)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Seed initial data
    feed_agg.seed_initial_data()
    telegram.seed_channels()
    monitor_thread.start()
    
    print("[+] Threat Intelligence Platform starting...")
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    print(f"[+] Dashboard:       http://{host}:{port}")
    print(f"[+] Dark Web Search: http://{host}:{port}/darkweb")
    print(f"[+] Telegram Monitor:http://{host}:{port}/telegram")
    print(f"[+] Threat Feeds:    http://{host}:{port}/feeds")
    print(f"[+] Credential Checker: http://{host}:{port}/credentials")
    print(f"[+] Tor Status:      http://{host}:{port}/api/tor/status")
    print(f"[*] Tor enabled: {TOR_ENABLED}, available: {TOR_AVAILABLE}")
    
    app.run(host=host, port=port, debug=False)
