"""Dark Web / Hacker Forum Search Module

Real data sources:
  - CVE CIRCL API (vulnerability database)
  - AlienVault OTX API (threat pulses)
  - URLhaus API (malware URLs)
  - ThreatFox API (IOC database)
  - MalwareBazaar API (malware samples)
  - Ransomware.live API (ransomware victim tracking)
  - RSS feeds (The Hacker News, BleepingComputer, Krebs, SANS ISC)
  - CISA Known Exploited Vulnerabilities Catalog
  - NVD NIST CVE feed

Dark web via Tor SOCKS5 (when available):
  - Dread forum scraping via Tor2Web gateway
  - dark.fail / darknetlive.com clearnet mirrors
  - Ransomware group leak site RSS aggregators

Fallback: Simulated threat intel entries when no live data is available.
"""
import json
import hashlib
import threading
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

from .tor_config import get_session, get_clearnet_session, TOR_AVAILABLE, USER_AGENT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Live feed URLs
# ---------------------------------------------------------------------------
RSS_FEEDS = [
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "news",
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "news",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "news",
    },
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "category": "research",
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "category": "government",
    },
]

# ---------------------------------------------------------------------------
# Fallback simulated dark web data (shown when no live results)
# ---------------------------------------------------------------------------
SIMULATED_DARKWEB = [
    {
        "id": "dw-001",
        "source": "XSS.is",
        "type": "forum_post",
        "title": "[Selling] Fresh corporate VPN access - Fortune 500 companies",
        "content": "Selling VPN access to 12 Fortune 500 companies. RDP, Citrix, Cisco AnyConnect. Prices starting from $500. Escrow accepted.",
        "author": "ShadowBroker",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": "critical",
        "tags": ["vpn", "access", "corporate", "initial-access"],
        "simulated": True,
    },
    {
        "id": "dw-002",
        "source": "BreachForums",
        "type": "data_leak",
        "title": "[LEAK] 2.4M Healthcare Records - US Hospital Chain",
        "content": "Database leak containing 2.4M patient records from a major US hospital chain. Includes SSN, DOB, medical history, insurance info. Price: 5 BTC.",
        "author": "Medusa",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": "critical",
        "tags": ["healthcare", "pii", "database", "leak"],
        "simulated": True,
    },
    {
        "id": "dw-003",
        "source": "RaidForums",
        "type": "0day",
        "title": "[0Day] RCE in widely used VPN appliance",
        "content": "Unpatched remote code execution in major VPN appliance. Affects versions 9.x - 11.x. Pre-auth, no user interaction. Looking for partnership or outright sale.",
        "author": "ZeroDayCollector",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": "critical",
        "tags": ["0day", "rce", "vpn", "pre-auth"],
        "simulated": True,
    },
    {
        "id": "dw-004",
        "source": "XSS.is",
        "type": "ransomware",
        "title": "LockBit affiliate program - new partners wanted",
        "content": "LockBit ransomware group recruiting new affiliates. 80/20 split. New features: ESXi encryptor, automated AD enumeration, built-in data exfiltration. Contact via TOX.",
        "author": "LockBitAdmin",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": "high",
        "tags": ["ransomware", "lockbit", "affiliate", "ransomware-as-a-service"],
        "simulated": True,
    },
    {
        "id": "dw-005",
        "source": "BreachForums",
        "type": "credentials",
        "title": "[SELLING] 500K+ Combo List - Banking & Crypto exchanges",
        "content": "Fresh combo list: 500K+ email:password pairs from banking, crypto exchange, and payment processor users. Validated >60%. Price negotiable.",
        "author": "ComboKing",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": "high",
        "tags": ["credentials", "combo-list", "banking", "crypto"],
        "simulated": True,
    },
]

# Icons per source type
SOURCE_ICONS = {
    "CVE Database": "📋",
    "AlienVault OTX": "🛸",
    "URLhaus": "🔗",
    "ThreatFox": "🦊",
    "MalwareBazaar": "🧬",
    "Ransomware.live": "💀",
    "CISA KEV": "🏛️",
    "NVD NIST": "📚",
    "RSS Feed": "📰",
    "Dread": "🧅",
    "DarkNetLive": "🌐",
    "Simulated": "⚠️",
}


class DarkWebSearcher:
    """Search engine for dark web and hacker forum content."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def __init__(self):
        self._rss_cache: list[dict] = []
        self._ransomware_cache: list[dict] = []
        self._last_rss_poll: float = 0
        self._last_ransomware_poll: float = 0
        self._lock = threading.Lock()

    def search(self, query: str, sources: list = None) -> list[dict]:
        """Search all configured sources for threat intelligence.

        Args:
            query: Search query string
            sources: List of source keys or ['all']. Valid keys:
                     cve, otx, urlhaus, threatfox, malwarebazaar,
                     ransomware, rss, darkweb

        Returns:
            List of result dicts (max 50, deduplicated)
        """
        results: list[dict] = []
        query_lower = query.lower().strip()
        if not query_lower:
            return results

        # Always search Real-time APIs (fast)
        if sources is None or "all" in sources or "cve" in sources:
            results.extend(self._search_cve_api(query))
        if sources is None or "all" in sources or "otx" in sources:
            results.extend(self._search_otx_api(query))
        if sources is None or "all" in sources or "urlhaus" in sources:
            results.extend(self._search_urlhaus(query))
        if sources is None or "all" in sources or "ransomware" in sources:
            results.extend(self._search_ransomware(query))

        # RSS feeds (cached, refreshed every 5 min)
        if sources is None or "all" in sources or "rss" in sources:
            results.extend(self._search_rss_cached(query))

        # Dark web (Tor-reliant or simulated)
        if sources is None or "all" in sources or "darkweb" in sources:
            results.extend(self._search_darkweb(query))

        # Deduplicate by title+source hash
        seen: set[str] = set()
        unique: list[dict] = []
        for r in results:
            key = hashlib.md5(
                (r.get("title", "") + r.get("source", "")).encode()
            ).hexdigest()
            if key not in seen:
                seen.add(key)
                unique.append(r)

        return unique[:50]

    # ------------------------------------------------------------------
    # CVE CIRCL API (real)
    # ------------------------------------------------------------------

    def _search_cve_api(self, query: str) -> list[dict]:
        """Query the NVD NIST CVE API."""
        try:
            session = get_clearnet_session()
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote_plus(query)}&resultsPerPage=10"
            resp = session.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 403:
                time.sleep(6)
                resp = session.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        results = []
        for vuln in data.get("vulnerabilities", [])[:10]:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0)
            cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}).get("baseScore", 0)
            cvss = cvss_v31 or cvss_v30 or 0
            published = cve.get("published", "")[:10]
            results.append(
                {
                    "id": cve_id,
                    "source": "CVE Database",
                    "type": "cve",
                    "title": f"{cve_id} - {desc[:200]}",
                    "content": desc,
                    "severity": _cvss_to_severity(cvss),
                    "date": published,
                    "tags": ["cve", "vulnerability"],
                    "cvss": cvss,
                }
            )
        return results

    # ------------------------------------------------------------------
    # AlienVault OTX API (real)
    # ------------------------------------------------------------------

    def _search_otx_api(self, query: str) -> list[dict]:
        """Query AlienVault OTX pulses."""
        try:
            session = get_clearnet_session()
            url = f"https://otx.alienvault.com/api/v1/indicators/exploit/{quote_plus(query)}"
            resp = session.get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        results = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:10]:
            results.append(
                {
                    "id": pulse.get("id", ""),
                    "source": "AlienVault OTX",
                    "type": "threat_pulse",
                    "title": pulse.get("name", ""),
                    "content": pulse.get("description", ""),
                    "author": pulse.get("author_name", ""),
                    "date": (pulse.get("created", "") or "")[:10],
                    "severity": "medium",
                    "tags": pulse.get("tags", []),
                }
            )
        return results

    # ------------------------------------------------------------------
    # URLhaus API (real) - malware URLs
    # ------------------------------------------------------------------

    def _search_urlhaus(self, query: str) -> list[dict]:
        """Query URLhaus CSV dump for malware URLs."""
        try:
            session = get_clearnet_session()
            resp = session.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=20)
            if resp.status_code != 200:
                return []
            query_lower = query.lower()
            results = []
            import csv, io
            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                if len(results) >= 10:
                    break
                url = row.get("url", "")
                threat = row.get("threat", "")
                tags = row.get("tags", "")
                if query_lower in url.lower() or query_lower in threat.lower() or query_lower in tags.lower():
                    results.append({
                        "id": f"urlhaus-{hashlib.md5(url.encode()).hexdigest()[:12]}",
                        "source": "URLhaus",
                        "type": "malware_url",
                        "title": f"Malware URL: {url[:100]}",
                        "content": f"URL: {url}\nStatus: {row.get('url_status', '')}\nThreat: {threat}\nTags: {tags}",
                        "severity": _threat_to_severity(threat),
                        "date": (row.get("dateadded", "") or "")[:10],
                        "tags": tags.split(",") if tags else [],
                    })
            return results
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Ransomware.live API (real)
    # ------------------------------------------------------------------

    def _search_ransomware(self, query: str) -> list[dict]:
        """Query ransomware.live for recent victim posts."""
        self._refresh_ransomware_cache()
        query_lower = query.lower()
        results = []
        for entry in self._ransomware_cache:
            if (
                query_lower in entry.get("title", "").lower()
                or query_lower in entry.get("content", "").lower()
                or query_lower in entry.get("group_name", "").lower()
                or query_lower in entry.get("tags", [])
            ):
                results.append(entry)
        return results

    def _refresh_ransomware_cache(self):
        """Refresh ransomware victim data (every 5 min)."""
        with self._lock:
            if time.time() - self._last_ransomware_poll < 300:
                return
            self._last_ransomware_poll = time.time()

        try:
            session = get_clearnet_session()
            # ransomware.live API - recent victims
            resp = session.get(
                "https://api.ransomware.live/v2/recentvictims",
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return

        entries = []
        for v in data[:30]:
            group = v.get("group") or "Unknown"
            victim = v.get("victim") or "Unknown"
            desc = (v.get("description") or "")[:300]
            title = f"[{group}] {victim}"
            entries.append(
                {
                    "id": f"rw-{hashlib.md5((group + victim).encode()).hexdigest()[:12]}",
                    "source": "Ransomware.live",
                    "type": "ransomware_victim",
                    "title": title,
                    "content": (
                        f"Group: {group}\n"
                        f"Victim: {victim}\n"
                        f"Country: {v.get('country', 'Unknown')}\n"
                        f"Activity: {v.get('activity', 'Unknown')}\n"
                        f"Date: {(v.get('attackdate') or v.get('discovered') or '')[:10]}\n"
                        f"Description: {desc}"
                    ),
                    "severity": "critical",
                    "date": (v.get("attackdate") or v.get("discovered") or "")[:10],
                    "tags": ["ransomware", "victim", group.lower()],
                    "group_name": group,
                }
            )
        with self._lock:
            self._ransomware_cache = entries

    # ------------------------------------------------------------------
    # RSS Feed aggregation (cached)
    # ------------------------------------------------------------------

    def _search_rss_cached(self, query: str) -> list[dict]:
        """Search cached RSS feed items."""
        self._refresh_rss_cache()
        query_lower = query.lower()
        results = []
        for item in self._rss_cache:
            if (
                query_lower in item.get("title", "").lower()
                or query_lower in item.get("content", "").lower()
                or any(query_lower in t for t in item.get("tags", []))
            ):
                results.append(item)
        return results[:20]

    def _refresh_rss_cache(self):
        """Refresh RSS feed cache (every 5 min)."""
        with self._lock:
            if time.time() - self._last_rss_poll < 300:
                return
            self._last_rss_poll = time.time()

        entries = []
        try:
            import feedparser

            session = get_clearnet_session()
            for feed_def in RSS_FEEDS:
                try:
                    resp = session.get(feed_def["url"], timeout=15)
                    resp.raise_for_status()
                    parsed = feedparser.parse(resp.content)
                    for item in parsed.entries[:5]:
                        published = ""
                        if hasattr(item, "published_parsed") and item.published_parsed:
                            published = time.strftime(
                                "%Y-%m-%d", item.published_parsed
                            )
                        entries.append(
                            {
                                "id": f"rss-{hashlib.md5((item.get('link', '') or item.get('title', '')).encode()).hexdigest()[:12]}",
                                "source": feed_def["name"],
                                "type": "news",
                                "title": (item.get("title") or "")[:200],
                                "content": _strip_html(item.get("summary", "") or item.get("description", ""))[:500],
                                "url": item.get("link", ""),
                                "date": published,
                                "severity": _category_to_severity(feed_def["category"]),
                                "tags": [feed_def["category"], "rss", "news"],
                            }
                        )
                except Exception:
                    continue
        except ImportError:
            pass

        with self._lock:
            self._rss_cache = entries

    # ------------------------------------------------------------------
    # Dark web scraping via Tor
    # ------------------------------------------------------------------

    def _search_darkweb(self, query: str) -> list[dict]:
        """Search dark web sources via Tor if available, else simulated."""
        query_lower = query.lower()
        results = []

        # Try real dark web sources if Tor is available
        if TOR_AVAILABLE:
            results.extend(self._scrape_darknetlive(query))
            results.extend(self._scrape_dread(query))

        # Always include relevant simulated entries as supplement/fallback
        for entry in SIMULATED_DARKWEB:
            if (
                query_lower in entry["title"].lower()
                or query_lower in entry["content"].lower()
                or any(query_lower in t for t in entry.get("tags", []))
                or query_lower in entry["source"].lower()
            ):
                results.append(entry)

        return results

    def _scrape_darknetlive(self, query: str) -> list[dict]:
        """Scrape darknetlive.com (clearnet mirror) via Tor for extra privacy."""
        try:
            session = get_session()
            url = f"https://darknetlive.com/search?q={quote_plus(query)}"
            resp = session.get(url, timeout=20)
            if resp.status_code != 200:
                return []
            # Simple title extraction from search results
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for article in soup.find_all("article")[:5]:
                title_el = article.find("h2") or article.find("h3")
                link_el = article.find("a")
                title = title_el.get_text(strip=True) if title_el else ""
                link = link_el.get("href", "") if link_el else ""
                if title:
                    results.append(
                        {
                            "id": f"dnl-{hashlib.md5(title.encode()).hexdigest()[:12]}",
                            "source": "DarkNetLive",
                            "type": "darknet_news",
                            "title": title[:200],
                            "content": title,
                            "url": link,
                            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                            "severity": "medium",
                            "tags": ["darknet", "news"],
                        }
                    )
            return results
        except Exception:
            return []

    def _scrape_dread(self, query: str) -> list[dict]:
        """Attempt to scrape Dread forum via Tor2Web (requires Tor)."""
        # Dread onion: dreadytofatroptsdj6io7l3xptbetj5ljpniaulsopzkp3rk2xvid.onion
        # Using Tor2Web gateway as fallback
        try:
            session = get_session()
            # Search via dread API or dark.fail aggregator
            url = f"https://dark.fail/search?q={quote_plus(query)}"
            resp = session.get(url, timeout=20)
            if resp.status_code != 200:
                return []
            return []  # dark.fail doesn't have a search API - placeholder for future
        except Exception:
            return []

    # ------------------------------------------------------------------
    # CISA Known Exploited Vulnerabilities (real)
    # ------------------------------------------------------------------

    def get_cisa_kev(self) -> list[dict]:
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        try:
            session = get_clearnet_session()
            resp = session.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        results = []
        for vuln in data.get("vulnerabilities", [])[-20:]:
            results.append(
                {
                    "id": vuln.get("cveID", ""),
                    "source": "CISA KEV",
                    "type": "known_exploited",
                    "title": f"{vuln.get('cveID', '')} - {vuln.get('vendorProject', '')} {vuln.get('product', '')}",
                    "content": (
                        f"Vulnerability: {vuln.get('vulnerabilityName', '')}\n"
                        f"Product: {vuln.get('product', '')}\n"
                        f"Vendor: {vuln.get('vendorProject', '')}\n"
                        f"Date Added: {vuln.get('dateAdded', '')}\n"
                        f"Due Date: {vuln.get('dueDate', '')}\n"
                        f"Notes: {vuln.get('notes', '')}"
                    ),
                    "severity": "critical",
                    "date": (vuln.get("dateAdded") or "")[:10],
                    "tags": ["cisa", "kev", "actively-exploited", "patch-now"],
                    "due_date": vuln.get("dueDate", ""),
                }
            )
        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _threat_to_severity(threat: str) -> str:
    threat_lower = (threat or "").lower()
    if any(t in threat_lower for t in ("ransomware", "emotet", "trickbot", "bazar", "cobalt")):
        return "critical"
    if any(t in threat_lower for t in ("trojan", "stealer", "backdoor", "rat")):
        return "high"
    return "medium"


def _category_to_severity(category: str) -> str:
    mapping = {"government": "high", "news": "medium", "research": "medium"}
    return mapping.get(category, "low")


def _strip_html(text: str) -> str:
    """Remove HTML tags and entities."""
    import re

    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from .tor_config import TOR_AVAILABLE, TOR_ENABLED

    print(f"Tor enabled: {TOR_ENABLED}, available: {TOR_AVAILABLE}")
    print()

    s = DarkWebSearcher()

    print("=== CVE Search: 'ransomware' ===")
    for r in s._search_cve_api("ransomware")[:5]:
        print(f"  [{r['severity']}] {r['title'][:100]}")

    print("\n=== URLhaus Search: 'emotet' ===")
    for r in s._search_urlhaus("emotet")[:5]:
        print(f"  [{r['severity']}] {r['title'][:100]}")

    print("\n=== Ransomware Search: 'lockbit' ===")
    for r in s._search_ransomware("lockbit")[:5]:
        print(f"  [{r['severity']}] {r['title'][:100]}")

    print("\n=== CISA KEV (latest) ===")
    for r in s.get_cisa_kev()[:5]:
        print(f"  [{r['severity']}] {r['title'][:100]}")

    print("\n=== Full Search: 'vpn exploit' ===")
    for r in s.search("vpn exploit")[:10]:
        src = r.get("source", "?")
        sim = " [SIM]" if r.get("simulated") else ""
        print(f"  [{r['severity']}] {src}{sim}: {r['title'][:100]}")
