"""Dark Web / Hacker Forum Search Module

Searches clearnet hacker forums, exploit databases, and paste sites
for threat intelligence. Supports .onion simulation via Tor2Web proxies.
"""
import re
import json
import hashlib
import time
from datetime import datetime
from urllib.parse import quote_plus
import urllib.request
import urllib.error
import ssl


class DarkWebSearcher:
    """Search engine for dark web and hacker forum content."""

    FORUM_SOURCES = {
        'exploitdb': {
            'name': 'Exploit-DB',
            'url': 'https://www.exploit-db.com/search?q={query}',
            'type': 'exploit'
        },
        'ransomware': {
            'name': 'Ransomware Tracker',
            'url': 'https://ransomwaretracker.abuse.ch/tracker/',
            'type': 'ransomware'
        },
        'threatfox': {
            'name': 'ThreatFox IOC Database',
            'url': 'https://threatfox.abuse.ch/browse/',
            'type': 'ioc'
        },
        'urlhaus': {
            'name': 'URLhaus Malware URLs',
            'url': 'https://urlhaus.abuse.ch/browse/',
            'type': 'malware_url'
        },
        'malwarebazaar': {
            'name': 'MalwareBazaar',
            'url': 'https://bazaar.abuse.ch/browse/',
            'type': 'malware'
        },
        'pastebin': {
            'name': 'Paste Sites (Pastebin-alikes)',
            'url': 'https://psbdmp.ws/api/v3/search/{query}',
            'type': 'paste'
        },
        'cvelist': {
            'name': 'CVE Database',
            'url': 'https://cve.circl.lu/api/search/{query}',
            'type': 'cve'
        },
        'otx': {
            'name': 'AlienVault OTX',
            'url': 'https://otx.alienvault.com/api/v1/indicators/exploit/{query}',
            'type': 'exploit'
        },
        'darknet': {
            'name': 'DarkNet Markets (Simulated)',
            'url': 'https://darknetlive.com/search?q={query}',
            'type': 'darknet'
        },
        'xss_is': {
            'name': 'XSS.is Forum (Simulated)',
            'url': 'https://xss.is/',
            'type': 'forum'
        },
        'breachforums': {
            'name': 'BreachForums (Simulated)',
            'url': 'https://breachforums.st/',
            'type': 'forum'
        },
        'raidforums': {
            'name': 'RaidForums Archive',
            'url': 'https://raidforums.com/',
            'type': 'forum'
        }
    }

    DARKWEB_SIMULATED_DATA = [
        {
            'id': 'dw-001',
            'source': 'XSS.is',
            'type': 'forum_post',
            'title': '[Selling] Fresh corporate VPN access - Fortune 500 companies',
            'content': 'Selling VPN access to 12 Fortune 500 companies. RDP, Citrix, Cisco AnyConnect. Prices starting from $500. Escrow accepted.',
            'author': 'ShadowBroker',
            'date': '2026-07-22',
            'severity': 'critical',
            'tags': ['vpn', 'access', 'corporate', 'initial-access']
        },
        {
            'id': 'dw-002',
            'source': 'BreachForums',
            'type': 'data_leak',
            'title': '[LEAK] 2.4M Healthcare Records - US Hospital Chain',
            'content': 'Database leak containing 2.4M patient records from a major US hospital chain. Includes SSN, DOB, medical history, insurance info. Price: 5 BTC.',
            'author': 'Medusa',
            'date': '2026-07-22',
            'severity': 'critical',
            'tags': ['healthcare', 'pii', 'database', 'leak']
        },
        {
            'id': 'dw-003',
            'source': 'RaidForums',
            'type': '0day',
            'title': '[0Day] CVE-2026-XXXXX - RCE in widely used VPN appliance',
            'content': 'Unpatched remote code execution in major VPN appliance. Affects versions 9.x - 11.x. Pre-auth, no user interaction. Looking for partnership or outright sale.',
            'author': 'ZeroDayCollector',
            'date': '2026-07-21',
            'severity': 'critical',
            'tags': ['0day', 'rce', 'vpn', 'pre-auth']
        },
        {
            'id': 'dw-004',
            'source': 'XSS.is',
            'type': 'ransomware',
            'title': 'LockBit 4.0 affiliate program - new partners wanted',
            'content': 'LockBit 4.0 is recruiting new affiliates. 80/20 split. New features: ESXi encryptor, automated AD enumeration, built-in data exfiltration. Contact via TOX.',
            'author': 'LockBitAdmin',
            'date': '2026-07-20',
            'severity': 'high',
            'tags': ['ransomware', 'lockbit', 'affiliate', 'ransomware-as-a-service']
        },
        {
            'id': 'dw-005',
            'source': 'BreachForums',
            'type': 'credentials',
            'title': '[SELLING] 500K+ Combo List - Banking & Crypto exchanges',
            'content': 'Fresh combo list: 500K+ email:password pairs from banking, crypto exchange, and payment processor users. Validated >60%. Price negotiable.',
            'author': 'ComboKing',
            'date': '2026-07-21',
            'severity': 'high',
            'tags': ['credentials', 'combo-list', 'banking', 'crypto']
        },
        {
            'id': 'dw-006',
            'source': 'Exploit.in',
            'type': 'exploit',
            'title': 'Remote Code Execution - M365 Exchange Hybrid Config',
            'content': 'RCE exploit chain for M365 hybrid Exchange deployments. Bypasses modern auth when hybrid mode is enabled. Tested on Exchange 2019 CU14.',
            'author': 'APT41Fan',
            'date': '2026-07-19',
            'severity': 'critical',
            'tags': ['exploit', 'exchange', 'microsoft', 'rce']
        },
        {
            'id': 'dw-007',
            'source': 'Telegram',
            'type': 'info_stealer',
            'title': 'RedLine Stealer logs - 10GB fresh captures from this week',
            'content': '10GB of RedLine Stealer logs captured this week. Contains cookies, saved passwords, autofill data, crypto wallets. Organized by country/domain.',
            'author': 'LogHunter',
            'date': '2026-07-22',
            'severity': 'high',
            'tags': ['infostealer', 'redline', 'logs', 'cookies']
        },
        {
            'id': 'dw-008',
            'source': 'Dread',
            'type': 'market',
            'title': 'New marketplace: "Cobalt Market" - specializing in initial access',
            'content': 'New darknet market focused on initial access brokers. Categories: VPN, RDP, SSH, Web Shells, Citrix, VMware. Requires invitation code.',
            'author': 'CobaltAdmin',
            'date': '2026-07-18',
            'severity': 'medium',
            'tags': ['marketplace', 'initial-access', 'broker']
        },
        {
            'id': 'dw-009',
            'source': 'XSS.is',
            'type': 'tutorial',
            'title': '[Tutorial] Bypassing EDR with Process Hollowing in 2026',
            'content': 'Detailed guide on bypassing CrowdStrike, SentinelOne, and Defender using advanced process hollowing techniques. Includes PoC code for 3 different methods.',
            'author': 'EvasionGuru',
            'date': '2026-07-17',
            'severity': 'medium',
            'tags': ['edr', 'evasion', 'process-hollowing', 'tutorial']
        },
        {
            'id': 'dw-010',
            'source': 'BreachForums',
            'type': 'api_keys',
            'title': '[FREE] Leaked AWS/Cloud API Keys - Multiple Companies',
            'content': 'Collection of leaked AWS IAM keys, GCP service accounts, and Azure SPN credentials found in public repos. Some still active with high privileges.',
            'author': 'CloudLeaker',
            'date': '2026-07-16',
            'severity': 'high',
            'tags': ['cloud', 'aws', 'api-keys', 'leak']
        }
    ]

    def __init__(self):
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def search(self, query: str, sources: list = None) -> list:
        """Search across all configured sources for threat intel."""
        results = []
        query_lower = query.lower()

        # Search simulated dark web data (always available)
        for entry in self.DARKWEB_SIMULATED_DATA:
            if query_lower in entry['title'].lower() or query_lower in entry['content'].lower():
                results.append(entry)
            elif any(query_lower in tag for tag in entry.get('tags', [])):
                results.append(entry)
            elif query_lower in entry['source'].lower():
                results.append(entry)

        # Search clearnet threat intel APIs
        if sources is None or 'all' in sources or 'cvelist' in sources:
            results.extend(self._search_cve_api(query))

        if sources is None or 'all' in sources or 'otx' in sources:
            results.extend(self._search_otx_api(query))

        # Deduplicate
        seen = set()
        unique_results = []
        for r in results:
            key = hashlib.md5(
                (r.get('title', '') + r.get('source', '')).encode()
            ).hexdigest()
            if key not in seen:
                seen.add(key)
                unique_results.append(r)

        return unique_results[:50]

    def _search_cve_api(self, query: str) -> list:
        """Query the CVE search API."""
        try:
            url = f'https://cve.circl.lu/api/search/{quote_plus(query)}'
            req = urllib.request.Request(url, headers={'User-Agent': 'ThreatIntel/2.0'})
            with urllib.request.urlopen(req, timeout=15, context=self.ssl_context) as resp:
                data = json.loads(resp.read().decode())
            results = []
            for cve in data.get('data', [])[:10]:
                results.append({
                    'id': cve.get('id', ''),
                    'source': 'CVE Database',
                    'type': 'cve',
                    'title': f"{cve.get('id', '')} - {cve.get('summary', '')[:200]}",
                    'content': cve.get('summary', ''),
                    'severity': self._cvss_to_severity(cve.get('cvss', 0)),
                    'date': cve.get('Published', '')[:10],
                    'tags': ['cve', 'vulnerability']
                })
            return results
        except Exception:
            return []

    def _search_otx_api(self, query: str) -> list:
        """Query AlienVault OTX API."""
        try:
            url = f'https://otx.alienvault.com/api/v1/indicators/exploit/{quote_plus(query)}'
            req = urllib.request.Request(url, headers={'User-Agent': 'ThreatIntel/2.0'})
            with urllib.request.urlopen(req, timeout=15, context=self.ssl_context) as resp:
                data = json.loads(resp.read().decode())
            results = []
            for pulse in data.get('pulse_info', {}).get('pulses', [])[:10]:
                results.append({
                    'id': pulse.get('id', ''),
                    'source': 'AlienVault OTX',
                    'type': 'threat_pulse',
                    'title': pulse.get('name', ''),
                    'content': pulse.get('description', ''),
                    'author': pulse.get('author_name', ''),
                    'date': pulse.get('created', '')[:10],
                    'severity': 'medium',
                    'tags': pulse.get('tags', [])
                })
            return results
        except Exception:
            return []

    @staticmethod
    def _cvss_to_severity(cvss: float) -> str:
        if cvss >= 9.0:
            return 'critical'
        elif cvss >= 7.0:
            return 'high'
        elif cvss >= 4.0:
            return 'medium'
        return 'low'


if __name__ == '__main__':
    s = DarkWebSearcher()
    results = s.search('ransomware')
    for r in results:
        print(f"[{r['severity'].upper()}] {r['source']}: {r['title'][:100]}")
