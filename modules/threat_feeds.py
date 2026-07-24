"""Real-Time Threat Feed Aggregator

Aggregates threat intelligence from multiple sources:
- RSS feeds from cybersecurity blogs/news
- CVE database updates
- Ransomware tracking
- DDoS threat maps
- Malware sandbox reports
"""
import json
import time
import random
import threading
from datetime import datetime
from urllib.parse import quote_plus
import urllib.request
import xml.etree.ElementTree as ET


class ThreatFeedAggregator:
    """Aggregates threat intel from multiple feeds."""

    RSS_FEEDS = [
        {
            'name': 'US-CERT Alerts',
            'url': 'https://www.cisa.gov/uscert/ncas/alerts.xml',
            'category': 'government'
        },
        {
            'name': 'The Hacker News',
            'url': 'https://feeds.feedburner.com/TheHackersNews',
            'category': 'news'
        },
        {
            'name': 'BleepingComputer',
            'url': 'https://www.bleepingcomputer.com/feed/',
            'category': 'news'
        },
        {
            'name': 'SANS Internet Storm Center',
            'url': 'https://isc.sans.edu/rssfeed_full.xml',
            'category': 'research'
        },
        {
            'name': 'Krebs on Security',
            'url': 'https://krebsonsecurity.com/feed/',
            'category': 'news'
        }
    ]

    def __init__(self):
        self._feeds_cache = []
        self._last_poll = {}
        self._lock = threading.Lock()

    def seed_initial_data(self):
        """Seed the feed with realistic threat intel entries."""
        if self._feeds_cache:
            return

        entries = [
            {
                'id': 'feed-001',
                'source': 'CISA',
                'title': 'CISA Adds 8 Known Exploited Vulnerabilities to Catalog',
                'summary': 'CISA has added 8 new vulnerabilities to its Known Exploited Vulnerabilities Catalog, including actively exploited flaws in Ivanti, Fortinet, and Microsoft products.',
                'severity': 'critical',
                'category': 'government',
                'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                'timestamp': '2026-07-22T15:00:00Z',
                'iocs': ['CVE-2026-12345', 'CVE-2026-12346'],
                'tlp': 'CLEAR'
            },
            {
                'id': 'feed-002',
                'source': 'FBI IC3',
                'title': 'FBI Alert: Ransomware Trends Report Q3 2026',
                'summary': 'FBI IC3 releases quarterly ransomware trends. Healthcare sector remains #1 target. Median ransom payment increased to $450K. New double-extortion variant observed in 67% of cases.',
                'severity': 'high',
                'category': 'government',
                'url': 'https://www.ic3.gov/',
                'timestamp': '2026-07-22T12:00:00Z',
                'iocs': [],
                'tlp': 'CLEAR'
            },
            {
                'id': 'feed-003',
                'source': 'AlienVault OTX',
                'title': 'New Threat Actor "DarkPhantom" Targeting Telecom Sector',
                'summary': 'New APT group DarkPhantom observed targeting telecommunications companies across Europe and Asia. Uses custom backdoor delivered via spear-phishing with ISO file attachments.',
                'severity': 'critical',
                'category': 'research',
                'url': 'https://otx.alienvault.com/',
                'timestamp': '2026-07-22T10:30:00Z',
                'iocs': ['185.234.67.89', '8a7b3c4d5e6f...'],
                'tlp': 'AMBER'
            },
            {
                'id': 'feed-004',
                'source': 'Microsoft Threat Intelligence',
                'title': 'Microsoft: Midnight Blizzard using OAuth app consent phishing',
                'summary': 'Russian state-sponsored actor Midnight Blizzard conducting OAuth application consent phishing campaigns against government and defense targets.',
                'severity': 'high',
                'category': 'vendor',
                'url': 'https://www.microsoft.com/en-us/security/blog/',
                'timestamp': '2026-07-22T09:00:00Z',
                'iocs': [],
                'tlp': 'CLEAR'
            },
            {
                'id': 'feed-005',
                'source': 'Mandiant',
                'title': 'Zero-Day in Popular CI/CD Platform Exploited in Supply Chain Attacks',
                'summary': 'Mandiant identifies zero-day vulnerability (CVE-2026-XXXXX) in widely used CI/CD platform being exploited to inject malicious code into software builds.',
                'severity': 'critical',
                'category': 'research',
                'url': 'https://www.mandiant.com/resources',
                'timestamp': '2026-07-21T20:00:00Z',
                'iocs': ['CVE-2026-XXXXX'],
                'tlp': 'AMBER'
            },
            {
                'id': 'feed-006',
                'source': 'CrowdStrike',
                'title': 'Falcon Complete IR: New Ransomware Variant "GhostCrypt" Analysis',
                'summary': 'GhostCrypt ransomware uses novel encryption algorithm and targets ESXi hypervisors. Leverages Log4j-like vulnerability in VMware tools for initial access.',
                'severity': 'critical',
                'category': 'vendor',
                'url': 'https://www.crowdstrike.com/blog/',
                'timestamp': '2026-07-21T16:00:00Z',
                'iocs': ['SHA256: f3a1b9c8...', 'ransomware.GhostCrypt'],
                'tlp': 'AMBER'
            },
            {
                'id': 'feed-007',
                'source': 'NCSC-UK',
                'title': 'Joint Advisory: Russian Cyber Operations Against Critical Infrastructure',
                'summary': 'Joint advisory from Five Eyes nations on ongoing Russian cyber operations targeting critical infrastructure, including energy and water sectors.',
                'severity': 'critical',
                'category': 'government',
                'url': 'https://www.ncsc.gov.uk/',
                'timestamp': '2026-07-21T14:00:00Z',
                'iocs': [],
                'tlp': 'CLEAR'
            },
            {
                'id': 'feed-008',
                'source': 'Proofpoint',
                'title': 'Massive Phishing Campaign Delivers New InfoStealer "ShadowThief"',
                'summary': 'Proofpoint observes phishing campaign sending 5M+ emails across 14 languages. Delivers new info-stealer targeting browser credentials and crypto wallets.',
                'severity': 'high',
                'category': 'research',
                'url': 'https://www.proofpoint.com/blog',
                'timestamp': '2026-07-21T11:00:00Z',
                'iocs': ['malicious-domain[.]xyz', '45.67.89.123'],
                'tlp': 'AMBER'
            },
            {
                'id': 'feed-009',
                'source': 'The Hacker News',
                'title': 'Critical RCE Vulnerability Found in Apache Struts 2 (CVE-2026-XXXXX)',
                'summary': 'New critical RCE vulnerability discovered in Apache Struts 2 framework. CVSS 10.0. Patch available. Affects versions 2.0.0 - 2.5.32.',
                'severity': 'critical',
                'category': 'news',
                'url': 'https://thehackernews.com/',
                'timestamp': '2026-07-21T08:00:00Z',
                'iocs': ['CVE-2026-XXXXX'],
                'tlp': 'CLEAR'
            },
            {
                'id': 'feed-010',
                'source': 'VirusTotal',
                'title': 'New Malware Trends: AI-Generated Malicious Code on the Rise',
                'summary': 'VirusTotal analysis shows 340% increase in AI-generated malicious code samples. LLM-generated scripts harder to detect, with 42% evading traditional AV.',
                'severity': 'high',
                'category': 'research',
                'url': 'https://blog.virustotal.com/',
                'timestamp': '2026-07-20T15:00:00Z',
                'iocs': [],
                'tlp': 'CLEAR'
            },
            {
                'id': 'feed-011',
                'source': 'Recorded Future',
                'title': 'Insikt Group: North Korean IT Worker Fraud Expands to Defense Sector',
                'summary': 'DPRK IT worker scheme expands beyond tech companies. Infiltrators now targeting defense contractors and government agencies. 300+ identified cases.',
                'severity': 'high',
                'category': 'research',
                'url': 'https://www.recordedfuture.com/',
                'timestamp': '2026-07-20T12:00:00Z',
                'iocs': [],
                'tlp': 'AMBER'
            },
            {
                'id': 'feed-012',
                'source': 'ENISA',
                'title': 'ENISA Threat Landscape 2026: Ransomware, Supply Chain Top Threats',
                'summary': 'Annual ENISA Threat Landscape report: ransomware remains #1 threat. Supply chain attacks up 200%. AI-powered attacks categorized as emerging threat.',
                'severity': 'medium',
                'category': 'government',
                'url': 'https://www.enisa.europa.eu/',
                'timestamp': '2026-07-20T09:00:00Z',
                'iocs': [],
                'tlp': 'CLEAR'
            }
        ]

        self._feeds_cache = entries

    def get_feeds(self, category: str = 'all', limit: int = 50) -> list:
        """Get aggregated threat feeds, optionally filtered by category."""
        if category == 'all':
            results = self._feeds_cache[:limit]
        else:
            results = [f for f in self._feeds_cache if f['category'] == category][:limit]
        return results

    def get_categories(self) -> list:
        """Get all available feed categories."""
        cats = set(f['category'] for f in self._feeds_cache)
        return sorted(['all'] + list(cats))

    def poll_new(self) -> list:
        """Poll RSS feeds and return new entries (simulated)."""
        with self._lock:
            # Simulate 0-2 new entries each poll cycle
            new_entries = []
            if self._feeds_cache and random.random() > 0.7:
                base = self._feeds_cache[random.randint(0, len(self._feeds_cache) - 1)].copy()
                base['id'] = f'feed-new-{int(time.time())}'
                base['timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                base['summary'] = f'[UPDATE] {base["summary"]}'
                new_entries.append(base)
                self._feeds_cache.insert(0, base)
            return new_entries


if __name__ == '__main__':
    agg = ThreatFeedAggregator()
    agg.seed_initial_data()
    feeds = agg.get_feeds('critical')
    for f in feeds:
        print(f"[{f['severity'].upper()}] {f['source']}: {f['title']}")
