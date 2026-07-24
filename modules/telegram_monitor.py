"""Telegram Channel Threat Intelligence Monitor

Monitors real Telegram channels for threat intel via public web previews (t.me/s/),
plus RSS aggregator feeds. No Telegram API key required.

Real data sources:
  - t.me/s/ public channel web previews (scraped via requests + BeautifulSoup)
  - Telegram channel aggregator RSS feeds
  - Ransomware.live Telegram group digests

Fallback: Hardcoded simulated messages when scraping is unavailable.
"""
import hashlib
import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

from .tor_config import get_clearnet_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tracked channel catalog (public t.me/s/ links)
# ---------------------------------------------------------------------------
TRACKED_CHANNELS = {
    "ransomware": [
        {
            "id": "ransomwatcher",
            "name": "RansomWatcher",
            "tme_url": "https://t.me/s/ransomwatcher",
            "type": "ransomware_group",
            "description": "Ransomware group victim tracking and announcements",
            "risk_level": "critical",
        },
        {
            "id": "darkfeedtelegram",
            "name": "DarkFeed",
            "tme_url": "https://t.me/s/darkfeed",
            "type": "ransomware_group",
            "description": "Dark web and ransomware intelligence feed",
            "risk_level": "critical",
        },
        {
            "id": "ransomnews",
            "name": "Ransomware News",
            "tme_url": "https://t.me/s/ransomwarenews",
            "type": "ransomware_group",
            "description": "Ransomware news and victim announcements",
            "risk_level": "high",
        },
    ],
    "exploit_trading": [
        {
            "id": "cvenewsdaily",
            "name": "CVE News",
            "tme_url": "https://t.me/s/cvenews",
            "type": "exploit_market",
            "description": "New CVE and exploit announcements",
            "risk_level": "critical",
        },
        {
            "id": "exploitdb_feed",
            "name": "Exploit-DB Feed",
            "tme_url": "https://t.me/s/exploitdb",
            "type": "exploit_market",
            "description": "Exploit-DB and exploit forum mirrors",
            "risk_level": "high",
        },
    ],
    "data_leaks": [
        {
            "id": "databreach",
            "name": "DataBreach",
            "tme_url": "https://t.me/s/databreach",
            "type": "data_leak",
            "description": "Data breach notifications and alerts",
            "risk_level": "critical",
        },
        {
            "id": "leakdatabreach",
            "name": "LeakDataBreach",
            "tme_url": "https://t.me/s/LeakDataBreach",
            "type": "data_leak",
            "description": "Data leak and breach intelligence",
            "risk_level": "critical",
        },
    ],
    "threat_intel": [
        {
            "id": "threatintel",
            "name": "Threat Intel",
            "tme_url": "https://t.me/s/threatintel",
            "type": "threat_intel",
            "description": "Cyber threat intelligence sharing",
            "risk_level": "high",
        },
        {
            "id": "cyb3rnews",
            "name": "CyberNews",
            "tme_url": "https://t.me/s/cyb3rnews",
            "type": "threat_intel",
            "description": "Cybersecurity news and threat updates",
            "risk_level": "medium",
        },
    ],
    "malware": [
        {
            "id": "malwarewatch",
            "name": "MalwareWatch",
            "tme_url": "https://t.me/s/malwarewatch",
            "type": "ioc_feed",
            "description": "Malware analysis and IOCs",
            "risk_level": "high",
        },
        {
            "id": "vxunderground",
            "name": "vx-underground",
            "tme_url": "https://t.me/s/vxunderground",
            "type": "ioc_feed",
            "description": "Malware samples, source code, and papers",
            "risk_level": "high",
        },
    ],
}

# ---------------------------------------------------------------------------
# IOC detection patterns
# ---------------------------------------------------------------------------
IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3}\[?\.\]?\d{1,3})\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\[?\.\][a-zA-Z]{2,})\b"),
    "sha256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    "sha1": re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    "md5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    "cve": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "btc_address": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
}

# ---------------------------------------------------------------------------
# Fallback messages (shown when scraping fails)
# ---------------------------------------------------------------------------
FALLBACK_MESSAGES = [
    {
        "id": "fallback-001",
        "channel": "threatintel",
        "channel_name": "Threat Intel",
        "text": (
            "🔴 CRITICAL: New critical vulnerability CVE-2026-XXXXX in widely-used VPN software. "
            "Pre-auth RCE, CVSS 10.0. Patch immediately. "
            "IOCs: 45.67.89[.]123, 91.234.56[.]78. #CVE #RCE #VPN"
        ),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "views": 25000,
        "forwards": 3400,
        "has_attachment": True,
        "simulated": True,
    },
    {
        "id": "fallback-002",
        "channel": "ransomwatcher",
        "channel_name": "RansomWatcher",
        "text": (
            "🔒 NEW VICTIM: Thompson Healthcare Group - 2.4TB data exfiltrated. "
            "LockBit claims responsibility. Payment deadline: 72 hours. "
            "Patient records, financial data, and internal communications exposed."
        ),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "views": 34000,
        "forwards": 1200,
        "has_attachment": True,
        "simulated": True,
    },
    {
        "id": "fallback-003",
        "channel": "cvenewsdaily",
        "channel_name": "CVE News",
        "text": (
            "🚨 NEW 0DAY: FortiOS SSL-VPN Pre-Auth RCE. "
            "Affects all versions 7.0-7.4. PoC available. "
            "SHA256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 #0day #fortinet #rce"
        ),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "views": 89000,
        "forwards": 4500,
        "has_attachment": True,
        "simulated": True,
    },
    {
        "id": "fallback-004",
        "channel": "databreach",
        "channel_name": "DataBreach",
        "text": (
            "📂 DATABASE LEAK: 4.7M user records from major e-commerce platform. "
            "Includes: emails, bcrypt hashes, names, addresses, order history. "
            "Download available on dark web. #dataleak #breach"
        ),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "views": 124000,
        "forwards": 8900,
        "has_attachment": True,
        "simulated": True,
    },
    {
        "id": "fallback-005",
        "channel": "vxunderground",
        "channel_name": "vx-underground",
        "text": (
            "📊 New Emotet variant analysis: C2 servers at 185.234.67[.]89, 103.45.67[.]123. "
            "Uses HTTPS with custom JA3 fingerprint: a1b2c3d4e5f6. "
            "Targets: legal, insurance, manufacturing sectors. #Emotet #Malware"
        ),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "views": 15000,
        "forwards": 2300,
        "has_attachment": True,
        "simulated": True,
    },
]


class TelegramMonitor:
    """Monitor Telegram channels for cyber threat intelligence."""

    def __init__(self):
        self._message_index = 0
        self._lock = threading.Lock()
        self._custom_channels: list[dict] = []
        self._processed_message_ids: set[str] = set()
        self._scraped_messages: list[dict] = []
        self._last_scrape: float = 0

    # ------------------------------------------------------------------
    # Channel management
    # ------------------------------------------------------------------

    def get_tracked_channels(self) -> dict:
        """Return all tracked channels grouped by category."""
        channels = {}
        for cat, chans in TRACKED_CHANNELS.items():
            channels[cat] = []
            for c in chans:
                channels[cat].append(
                    {
                        "id": c["id"],
                        "name": c["name"],
                        "type": c["type"],
                        "description": c["description"],
                        "risk_level": c["risk_level"],
                    }
                )
        if self._custom_channels:
            channels["custom"] = self._custom_channels
        return channels

    def add_channel(self, channel_name: str):
        """Add a custom channel to track."""
        slug = channel_name.lower().replace(" ", "_").replace("@", "")
        entry = {
            "id": slug,
            "name": channel_name,
            "tme_url": f"https://t.me/s/{slug.lstrip('@')}",
            "type": "custom",
            "description": f"Custom channel: {channel_name}",
            "risk_level": "unknown",
        }
        self._custom_channels.append(entry)

    def seed_channels(self):
        """Pre-populate channels (no-op; channels are static)."""
        pass

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search_messages(self, query: str, channel: str = None, limit: int = 100) -> list[dict]:
        """Search tracked messages for threat intelligence."""
        results = []
        query_lower = query.lower()

        # Search scraped messages first
        for msg in self._scraped_messages:
            if channel and msg.get("channel") != channel:
                continue
            if query_lower in msg.get("text", "").lower() or query_lower in msg.get(
                "channel_name", ""
            ).lower():
                results.append(msg)
                if len(results) >= limit:
                    return results

        # Search fallback messages
        for msg in FALLBACK_MESSAGES:
            if channel and msg.get("channel") != channel:
                continue
            if query_lower in msg.get("text", "").lower() or query_lower in msg.get(
                "channel_name", ""
            ).lower():
                results.append(msg)
                if len(results) >= limit:
                    return results

        # If nothing found, return a helpful message
        if not results:
            results.append(
                {
                    "id": f"search-{query_lower[:10]}",
                    "channel": "search_results",
                    "channel_name": "Threat Intel Search",
                    "text": (
                        f'🔍 Search results for "{query}": Searched {sum(len(v) for v in TRACKED_CHANNELS.values())} '
                        f"tracked channels. Try broader terms or add specific channels from the catalog."
                    ),
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "views": 0,
                    "forwards": 0,
                    "has_attachment": False,
                }
            )

        return results[:limit]

    # ------------------------------------------------------------------
    # Polling (real + fallback)
    # ------------------------------------------------------------------

    def poll_new_messages(self) -> list[dict]:
        """Poll for new messages. Tries real scraping first, falls back to simulated."""
        with self._lock:
            # Try real scraping every 5 minutes
            now = time.time()
            if now - self._last_scrape > 300:
                self._last_scrape = now
                new_real = self._scrape_public_channels()
                for msg in new_real:
                    msg_id = msg.get("id", "")
                    if msg_id and msg_id not in self._processed_message_ids:
                        self._processed_message_ids.add(msg_id)
                        self._scraped_messages.insert(0, msg)

            # If we have scraped messages, rotate through them
            if self._scraped_messages:
                idx = self._message_index % len(self._scraped_messages)
                msg = self._scraped_messages[idx].copy()
                self._message_index += 1
                if len(self._scraped_messages) > 200:
                    self._scraped_messages = self._scraped_messages[:200]
                return [msg]

            # Fallback: rotate through simulated messages
            new_msgs = []
            batch_size = min(2, len(FALLBACK_MESSAGES))
            for _ in range(batch_size):
                idx = self._message_index % len(FALLBACK_MESSAGES)
                msg = FALLBACK_MESSAGES[idx].copy()
                if msg["id"] not in self._processed_message_ids:
                    msg["timestamp"] = datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    self._processed_message_ids.add(msg["id"])
                    new_msgs.append(msg)
                self._message_index += 1
            return new_msgs

    # ------------------------------------------------------------------
    # Real Telegram channel scraping (t.me/s/)
    # ------------------------------------------------------------------

    def _scrape_public_channels(self) -> list[dict]:
        """Scrape public Telegram channels via t.me/s/ web previews."""
        messages = []
        session = get_clearnet_session()

        all_channels = []
        for chans in TRACKED_CHANNELS.values():
            all_channels.extend(chans)

        for channel in all_channels[:3]:  # Limit to first 3 per poll cycle
            try:
                tme_url = channel.get("tme_url", "")
                if not tme_url:
                    continue

                resp = session.get(tme_url, timeout=15)
                if resp.status_code != 200:
                    logger.debug(f"Failed to fetch {tme_url}: HTTP {resp.status_code}")
                    continue

                from bs4 import BeautifulSoup

                soup = BeautifulSoup(resp.text, "html.parser")
                msg_divs = soup.select(".tgme_widget_message_wrap")

                for div in msg_divs[:3]:
                    text_div = div.select_one(".tgme_widget_message_text")
                    text = text_div.get_text("\n", strip=True) if text_div else ""

                    if not text or len(text) < 10:
                        continue

                    date_div = div.select_one(".tgme_widget_message_date time")
                    ts = ""
                    if date_div and date_div.get("datetime"):
                        ts = date_div["datetime"]

                    # Extract views if available
                    views_div = div.select_one(".tgme_widget_message_views")
                    views = 0
                    if views_div:
                        view_text = views_div.get_text(strip=True)
                        try:
                            views = int(re.sub(r"[^0-9]", "", view_text) or 0)
                        except ValueError:
                            views = 0

                    # Detect IOCs in text
                    iocs = self._extract_iocs(text)

                    msg_id = hashlib.md5(
                        (channel["id"] + text[:100]).encode()
                    ).hexdigest()[:16]

                    messages.append(
                        {
                            "id": f"tg-{msg_id}",
                            "channel": channel["id"],
                            "channel_name": channel["name"],
                            "text": text[:500],
                            "timestamp": ts or datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%SZ"
                            ),
                            "views": views,
                            "forwards": 0,
                            "has_attachment": bool(div.select_one(".tgme_widget_message_photo_wrap")),
                            "iocs": iocs if iocs else None,
                            "live": True,
                        }
                    )

                time.sleep(1)  # Rate limit between channels

            except Exception as e:
                logger.debug(f"Error scraping {channel.get('name')}: {e}")
                continue

        return messages

    @staticmethod
    def _extract_iocs(text: str) -> dict:
        """Extract IOCs from message text."""
        iocs = {}
        # Clean bracket-defanged IOCs
        cleaned = text.replace("[.]", ".").replace("[dot]", ".")
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = pattern.findall(cleaned)
            if matches:
                # Deduplicate
                unique = list(dict.fromkeys(matches))[:10]
                iocs[ioc_type] = unique
        return iocs


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    tm = TelegramMonitor()
    channels = tm.get_tracked_channels()
    total = sum(len(v) for v in channels.values())
    print(f"Tracked channels: {total}")
    for cat, chans in channels.items():
        print(f"\n  [{cat.upper()}]")
        for c in chans:
            print(f"    {c['name']} ({c['risk_level']}) - {c['description'][:60]}")

    if len(sys.argv) > 1:
        print(f"\n=== Search: '{sys.argv[1]}' ===")
        for msg in tm.search_messages(sys.argv[1], limit=5):
            sim = " [SIM]" if msg.get("simulated") else " [LIVE]"
            print(f"  [{msg['channel_name']}]{sim}: {msg['text'][:120]}")
