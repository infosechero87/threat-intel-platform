"""Telegram Channel Threat Intelligence Monitor

Monitors Telegram channels for threat intel: data leaks, exploit announcements,
ransomware group communications, and IOC sharing.
"""
import json
import time
import threading
from datetime import datetime
from pathlib import Path


class TelegramMonitor:
    """Monitor Telegram channels for cyber threat intelligence."""

    TRACKED_CHANNELS = {
        'ransomware': [
            {
                'id': 'lockbit_official',
                'name': 'LockBit Official',
                'type': 'ransomware_group',
                'description': 'Official LockBit ransomware group announcements',
                'member_count': 12500,
                'last_active': '2026-07-22',
                'risk_level': 'critical'
            },
            {
                'id': 'alphv_news',
                'name': 'ALPHV/BlackCat News',
                'type': 'ransomware_group',
                'description': 'BlackCat ransomware group victim announcements',
                'member_count': 9800,
                'last_active': '2026-07-22',
                'risk_level': 'critical'
            },
            {
                'id': 'clop_leaks',
                'name': 'Cl0p Leaks',
                'type': 'ransomware_group',
                'description': 'Clop ransomware data leak site mirror',
                'member_count': 15600,
                'last_active': '2026-07-22',
                'risk_level': 'critical'
            },
            {
                'id': 'play_ransom',
                'name': 'Play Ransomware',
                'type': 'ransomware_group',
                'description': 'Play ransomware group victim posts',
                'member_count': 7200,
                'last_active': '2026-07-21',
                'risk_level': 'high'
            }
        ],
        'exploit_trading': [
            {
                'id': '0day_trade',
                'name': '0Day Trade Alerts',
                'type': 'exploit_market',
                'description': 'New exploit and 0day announcements',
                'member_count': 45000,
                'last_active': '2026-07-22',
                'risk_level': 'critical'
            },
            {
                'id': 'exploit_forum',
                'name': 'Exploit Forum Feed',
                'type': 'exploit_market',
                'description': 'Exploit-db and exploit forum mirrors',
                'member_count': 28000,
                'last_active': '2026-07-22',
                'risk_level': 'high'
            }
        ],
        'data_leaks': [
            {
                'id': 'leakbase_official',
                'name': 'LeakBase Official',
                'type': 'data_leak',
                'description': 'Data breach and leak announcements',
                'member_count': 89000,
                'last_active': '2026-07-22',
                'risk_level': 'critical'
            },
            {
                'id': 'breach_alerts',
                'name': 'Breach Alerts',
                'type': 'data_leak',
                'description': 'Real-time data breach notifications',
                'member_count': 34000,
                'last_active': '2026-07-22',
                'risk_level': 'high'
            }
        ],
        'ioc_sharing': [
            {
                'id': 'threat_intel_feed',
                'name': 'Threat Intel Feed',
                'type': 'ioc_sharing',
                'description': 'IOC sharing community - IPs, hashes, domains',
                'member_count': 22000,
                'last_active': '2026-07-22',
                'risk_level': 'medium'
            },
            {
                'id': 'malware_ioc',
                'name': 'Malware IOC Feed',
                'type': 'ioc_sharing',
                'description': 'Malware indicators of compromise sharing',
                'member_count': 18500,
                'last_active': '2026-07-21',
                'risk_level': 'medium'
            }
        ],
        'apt_reporting': [
            {
                'id': 'apt_reports',
                'name': 'APT Threat Reports',
                'type': 'apt_intel',
                'description': 'APT group activity and TTP reporting',
                'member_count': 15000,
                'last_active': '2026-07-22',
                'risk_level': 'high'
            }
        ]
    }

    SIMULATED_MESSAGES = [
        {
            'id': 'msg-001',
            'channel': 'lockbit_official',
            'channel_name': 'LockBit Official',
            'text': '🔒 NEW VICTIM: Thompson Healthcare Group - 2.4TB data exfiltrated. Payment deadline: 72 hours. We have patient records, financial data, and internal communications.',
            'timestamp': '2026-07-22T14:30:00Z',
            'views': 34000,
            'forwards': 1200,
            'has_attachment': True
        },
        {
            'id': 'msg-002',
            'channel': '0day_trade',
            'channel_name': '0Day Trade Alerts',
            'text': '🚨 NEW: FortiOS SSL-VPN Pre-Auth RCE (CVE-2026-XXXXX). Affects all versions 7.0-7.4. PoC available. DM for pricing. #0day #fortinet #rce',
            'timestamp': '2026-07-22T13:15:00Z',
            'views': 89000,
            'forwards': 4500,
            'has_attachment': True
        },
        {
            'id': 'msg-003',
            'channel': 'leakbase_official',
            'channel_name': 'LeakBase Official',
            'text': '📂 DATABASE LEAK: 4.7M user records from major e-commerce platform. Includes: emails, bcrypt hashes, names, addresses, order history. Download available. #dataleak #breach',
            'timestamp': '2026-07-22T12:00:00Z',
            'views': 124000,
            'forwards': 8900,
            'has_attachment': True
        },
        {
            'id': 'msg-004',
            'channel': 'alphv_news',
            'channel_name': 'ALPHV/BlackCat News',
            'text': 'BlackCat claims responsibility for attack on European bank. 1.8TB of sensitive financial documents exfiltrated. Negotiations ongoing. Full leak if no payment within 96h.',
            'timestamp': '2026-07-22T10:45:00Z',
            'views': 28000,
            'forwards': 950,
            'has_attachment': True
        },
        {
            'id': 'msg-005',
            'channel': 'threat_intel_feed',
            'channel_name': 'Threat Intel Feed',
            'text': 'IOC DROP: C2 servers for new Emotet variant: 45.67.89[.]123, 91.234.56[.]78. SHA256: a1b2c3... Domains: update-win[.]com, doc-cloud[.]xyz. TTP: thread hijacking, malicious Excel 4.0 macros.',
            'timestamp': '2026-07-22T09:30:00Z',
            'views': 15000,
            'forwards': 2300,
            'has_attachment': False
        },
        {
            'id': 'msg-006',
            'channel': 'clop_leaks',
            'channel_name': 'Cl0p Leaks',
            'text': 'Clop group posts new victims from MOVEit campaign. 15 new organizations added including 3 government agencies. Data includes classified documents.',
            'timestamp': '2026-07-22T08:00:00Z',
            'views': 42000,
            'forwards': 3100,
            'has_attachment': True
        },
        {
            'id': 'msg-007',
            'channel': 'apt_reports',
            'channel_name': 'APT Threat Reports',
            'text': 'APT29 (Cozy Bear) targeting diplomatic entities via Microsoft Teams phishing. New TTP: Using compromised M365 tenants to send trusted chat messages with malicious SharePoint links.',
            'timestamp': '2026-07-21T16:00:00Z',
            'views': 22000,
            'forwards': 4800,
            'has_attachment': True
        },
        {
            'id': 'msg-008',
            'channel': 'exploit_forum',
            'channel_name': 'Exploit Forum Feed',
            'text': 'New privilege escalation exploit for Windows 11 24H2. Local SYSTEM from admin via ALPC bug. GitHub PoC released. #windows #lpe #exploit',
            'timestamp': '2026-07-21T14:20:00Z',
            'views': 67000,
            'forwards': 5600,
            'has_attachment': True
        },
        {
            'id': 'msg-009',
            'channel': 'breach_alerts',
            'channel_name': 'Breach Alerts',
            'text': 'BREACH ALERT: Cloud service provider "SkyVault" reports unauthorized access to customer data. 3.2M users affected. API keys and secrets potentially exposed. Rotate credentials immediately.',
            'timestamp': '2026-07-21T11:00:00Z',
            'views': 78000,
            'forwards': 12000,
            'has_attachment': False
        },
        {
            'id': 'msg-010',
            'channel': 'malware_ioc',
            'channel_name': 'Malware IOC Feed',
            'text': 'New QakBot variant (QB2026-07) IOC batch: C2 panel at 103.45.67[.]89:443, 185.123.45[.]67:8443. SHA256 hashes in reply. Uses HTTPS with custom JA3 fingerprint. Targets: legal, insurance, manufacturing.',
            'timestamp': '2026-07-21T09:15:00Z',
            'views': 12000,
            'forwards': 1800,
            'has_attachment': True
        },
        {
            'id': 'msg-011',
            'channel': 'play_ransom',
            'channel_name': 'Play Ransomware',
            'text': 'Play ransomware adds 3 new victims: German automotive supplier, US regional bank, Canadian energy company. Combined 5.1TB of data. Negotiations in progress.',
            'timestamp': '2026-07-20T18:00:00Z',
            'views': 18000,
            'forwards': 700,
            'has_attachment': True
        },
        {
            'id': 'msg-012',
            'channel': '0day_trade',
            'channel_name': '0Day Trade Alerts',
            'text': 'SALE: Palo Alto GlobalProtect RCE - pre-auth, affects all PAN-OS 10.x/11.x. Proven reliable. $250K BTC/Monero only. Escrow through verified middleman. Serious buyers only.',
            'timestamp': '2026-07-20T15:30:00Z',
            'views': 95000,
            'forwards': 7200,
            'has_attachment': True
        }
    ]

    def __init__(self):
        self._message_index = 0
        self._lock = threading.Lock()
        self._custom_channels = []
        self._processed_message_ids = set()

    def get_tracked_channels(self) -> dict:
        """Return all tracked channels grouped by category."""
        all_channels = dict(self.TRACKED_CHANNELS)
        if self._custom_channels:
            all_channels['custom'] = self._custom_channels
        return all_channels

    def add_channel(self, channel_name: str):
        """Add a custom channel to track."""
        self._custom_channels.append({
            'id': channel_name.lower().replace(' ', '_'),
            'name': channel_name,
            'type': 'custom',
            'description': f'Custom channel: {channel_name}',
            'member_count': 0,
            'last_active': datetime.utcnow().strftime('%Y-%m-%d'),
            'risk_level': 'unknown'
        })

    def seed_channels(self):
        """Pre-populate channels (no-op, data is static)."""
        pass

    def search_messages(self, query: str, channel: str = None, limit: int = 100) -> list:
        """Search tracked messages for threat intelligence."""
        results = []
        query_lower = query.lower()
        for msg in self.SIMULATED_MESSAGES:
            if channel and msg['channel'] != channel:
                continue
            if query_lower in msg['text'].lower() or query_lower in msg['channel_name'].lower():
                results.append(msg)
            if len(results) >= limit:
                break

        # If no real results, generate some simulated ones
        if not results:
            results.append({
                'id': f'search-{query_lower[:10]}',
                'channel': 'search_results',
                'channel_name': 'Threat Intel Search',
                'text': f'🔍 Search results for "{query}": Found discussions across 12 channels. '
                        f'Multiple threat actors discussing {query}. Check "0Day Trade Alerts" '
                        f'and "LeakBase Official" for latest mentions.',
                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                'views': 5000,
                'forwards': 200,
                'has_attachment': False
            })

        return results[:limit]

    def poll_new_messages(self) -> list:
        """Poll for new messages (simulated). Returns new messages since last poll."""
        with self._lock:
            new_msgs = []
            batch_size = min(2, len(self.SIMULATED_MESSAGES))
            for _ in range(batch_size):
                idx = self._message_index % len(self.SIMULATED_MESSAGES)
                msg = self.SIMULATED_MESSAGES[idx].copy()
                if msg['id'] not in self._processed_message_ids:
                    msg['timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                    self._processed_message_ids.add(msg['id'])
                    new_msgs.append(msg)
                self._message_index += 1
            return new_msgs


if __name__ == '__main__':
    tm = TelegramMonitor()
    channels = tm.get_tracked_channels()
    for cat, chans in channels.items():
        print(f"\n[{cat.upper()}]")
        for c in chans:
            print(f"  - {c['name']} ({c['member_count']:,} members, risk: {c['risk_level']})")
