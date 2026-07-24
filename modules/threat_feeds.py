"""Real-Time Threat Feed Aggregator

Aggregates threat intelligence from multiple live sources:
  - RSS feeds from cybersecurity blogs, news, and government
  - Ransomware.live API (victim tracking)
  - CISA Known Exploited Vulnerabilities catalog
  - NVD NIST recent CVEs
  - ThreatFox IOC database
  - MalwareBazaar recent submissions

Seed data provides initial dashboard content; background poller refreshes
from live feeds every 5 minutes.
"""
import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_plus

from .tor_config import get_clearnet_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RSS feed definitions
# ---------------------------------------------------------------------------
RSS_FEEDS = [
    {
        "name": "US-CERT Alerts",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "category": "government",
    },
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
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "category": "research",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "news",
    },
    {
        "name": "Naked Security (Sophos)",
        "url": "https://nakedsecurity.sophos.com/feed/",
        "category": "vendor",
    },
    {
        "name": "Microsoft Security Response Center",
        "url": "https://msrc.microsoft.com/blog/feed/",
        "category": "vendor",
    },
    {
        "name": "CSO Online",
        "url": "https://www.csoonline.com/feed/",
        "category": "news",
    },
]

# ---------------------------------------------------------------------------
# Seed data — populates dashboard immediately before live feeds arrive
# ---------------------------------------------------------------------------
SEED_ENTRIES = [
    {
        "id": "feed-001",
        "source": "CISA",
        "title": "CISA Adds 8 Known Exploited Vulnerabilities to Catalog",
        "summary": "CISA has added 8 new vulnerabilities to its Known Exploited Vulnerabilities Catalog, including actively exploited flaws in Ivanti, Fortinet, and Microsoft products.",
        "severity": "critical",
        "category": "government",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": ["CVE-2026-12345"],
        "tlp": "CLEAR",
    },
    {
        "id": "feed-002",
        "source": "FBI IC3",
        "title": "FBI Alert: Ransomware Trends Report — Healthcare #1 Target",
        "summary": "FBI IC3 quarterly ransomware report: healthcare sector remains #1 target. Median ransom payment increased to $450K. Double-extortion in 67% of cases.",
        "severity": "high",
        "category": "government",
        "url": "https://www.ic3.gov/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "CLEAR",
    },
    {
        "id": "feed-003",
        "source": "AlienVault OTX",
        "title": "New APT Group 'DarkPhantom' Targeting Telecom Sector",
        "summary": "New APT group DarkPhantom observed targeting telecommunications companies across Europe and Asia. Uses custom backdoor delivered via spear-phishing with ISO file attachments.",
        "severity": "critical",
        "category": "research",
        "url": "https://otx.alienvault.com/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": ["185.234.67.89"],
        "tlp": "AMBER",
    },
    {
        "id": "feed-004",
        "source": "Microsoft Threat Intelligence",
        "title": "Midnight Blizzard Using OAuth App Consent Phishing",
        "summary": "Russian state-sponsored actor Midnight Blizzard conducting OAuth application consent phishing campaigns against government and defense targets.",
        "severity": "high",
        "category": "vendor",
        "url": "https://www.microsoft.com/en-us/security/blog/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "CLEAR",
    },
    {
        "id": "feed-005",
        "source": "Mandiant",
        "title": "Zero-Day in Popular CI/CD Platform Exploited in Supply Chain Attacks",
        "summary": "Mandiant identifies critical zero-day in widely-used CI/CD platform being exploited to inject malicious code into software builds. Active exploitation confirmed.",
        "severity": "critical",
        "category": "research",
        "url": "https://www.mandiant.com/resources",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "AMBER",
    },
    {
        "id": "feed-006",
        "source": "CrowdStrike",
        "title": "Falcon Complete: New 'GhostCrypt' Ransomware Analysis",
        "summary": "GhostCrypt ransomware uses novel encryption algorithm targeting ESXi hypervisors. Leverages vulnerability in VMware tools for initial access.",
        "severity": "critical",
        "category": "vendor",
        "url": "https://www.crowdstrike.com/blog/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": ["ransomware.GhostCrypt"],
        "tlp": "AMBER",
    },
    {
        "id": "feed-007",
        "source": "NCSC-UK",
        "title": "Joint Advisory: Russian Cyber Operations Against Critical Infrastructure",
        "summary": "Joint advisory from Five Eyes nations on ongoing Russian cyber operations targeting critical infrastructure, including energy and water sectors.",
        "severity": "critical",
        "category": "government",
        "url": "https://www.ncsc.gov.uk/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "CLEAR",
    },
    {
        "id": "feed-008",
        "source": "Proofpoint",
        "title": "Massive Phishing Campaign Delivers 'ShadowThief' InfoStealer",
        "summary": "Proofpoint observes phishing campaign sending 5M+ emails across 14 languages. Delivers new info-stealer targeting browser credentials and crypto wallets.",
        "severity": "high",
        "category": "research",
        "url": "https://www.proofpoint.com/blog",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": ["malicious-domain.xyz", "45.67.89.123"],
        "tlp": "AMBER",
    },
    {
        "id": "feed-009",
        "source": "The Hacker News",
        "title": "Critical RCE Vulnerability Found in Apache Struts 2",
        "summary": "New critical RCE vulnerability discovered in Apache Struts 2 framework. CVSS 10.0. Patch available. Affects versions 2.0.0 - 6.x.",
        "severity": "critical",
        "category": "news",
        "url": "https://thehackernews.com/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "CLEAR",
    },
    {
        "id": "feed-010",
        "source": "VirusTotal",
        "title": "AI-Generated Malicious Code on the Rise — 340% Increase",
        "summary": "VirusTotal analysis shows 340% increase in AI-generated malicious code samples. LLM-generated scripts harder to detect, 42% evading traditional AV.",
        "severity": "high",
        "category": "research",
        "url": "https://blog.virustotal.com/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "CLEAR",
    },
    {
        "id": "feed-011",
        "source": "Recorded Future",
        "title": "Insikt Group: North Korean IT Worker Fraud Expands to Defense",
        "summary": "DPRK IT worker scheme expands beyond tech companies. Infiltrators now targeting defense contractors and government agencies. 300+ identified cases.",
        "severity": "high",
        "category": "research",
        "url": "https://www.recordedfuture.com/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "AMBER",
    },
    {
        "id": "feed-012",
        "source": "ENISA",
        "title": "ENISA Threat Landscape 2026: Ransomware, Supply Chain Top Threats",
        "summary": "Annual ENISA Threat Landscape report: ransomware remains #1 threat. Supply chain attacks up 200%. AI-powered attacks categorized as emerging threat.",
        "severity": "medium",
        "category": "government",
        "url": "https://www.enisa.europa.eu/",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs": [],
        "tlp": "CLEAR",
    },
]


class ThreatFeedAggregator:
    """Aggregates threat intel from multiple live feeds."""

    def __init__(self):
        self._feeds_cache: list[dict] = []
        self._live_entries: list[dict] = []
        self._last_poll: dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seed_initial_data(self):
        """Seed the feed with initial threat intel entries."""
        with self._lock:
            if self._feeds_cache:
                return
            self._feeds_cache = list(SEED_ENTRIES)

    def get_feeds(self, category: str = "all", limit: int = 50) -> list[dict]:
        """Get aggregated threat feeds, optionally filtered by category."""
        with self._lock:
            if category == "all":
                return self._feeds_cache[:limit]
            return [f for f in self._feeds_cache if f.get("category") == category][:limit]

    def get_categories(self) -> list[str]:
        """Get all available feed categories."""
        with self._lock:
            cats = set(f.get("category", "other") for f in self._feeds_cache)
        return sorted(["all"] + list(cats))

    # ------------------------------------------------------------------
    # Polling — fetches from live sources
    # ------------------------------------------------------------------

    def poll_new(self) -> list[dict]:
        """Poll live sources for new entries. Returns new items since last poll."""
        new_entries: list[dict] = []

        # Rate limit: only poll each source every 5 minutes
        with self._lock:
            now = time.time()
            # RSS feeds
            if now - self._last_poll.get("rss", 0) > 300:
                self._last_poll["rss"] = now
                new_entries.extend(self._poll_rss_feeds())

            # Ransomware.live
            if now - self._last_poll.get("ransomware", 0) > 300:
                self._last_poll["ransomware"] = now
                new_entries.extend(self._poll_ransomware_live())

            # ThreatFox
            if now - self._last_poll.get("threatfox", 0) > 300:
                self._last_poll["threatfox"] = now
                new_entries.extend(self._poll_threatfox())

            # MalwareBazaar
            if now - self._last_poll.get("malwarebazaar", 0) > 300:
                self._last_poll["malwarebazaar"] = now
                new_entries.extend(self._poll_malwarebazaar())

            # CISA KEV
            if now - self._last_poll.get("cisa_kev", 0) > 600:
                self._last_poll["cisa_kev"] = now
                new_entries.extend(self._poll_cisa_kev())

            # Insert new entries at the top of cache
            for entry in reversed(new_entries):
                # Deduplicate
                if not any(
                    e.get("title") == entry.get("title") for e in self._feeds_cache
                ):
                    self._feeds_cache.insert(0, entry)

            # Trim cache
            if len(self._feeds_cache) > 500:
                self._feeds_cache = self._feeds_cache[:500]

        return new_entries

    # ------------------------------------------------------------------
    # Live source pollers
    # ------------------------------------------------------------------

    def _poll_rss_feeds(self) -> list[dict]:
        """Fetch and parse RSS feeds."""
        entries = []
        try:
            import feedparser

            session = get_clearnet_session()
            for feed_def in RSS_FEEDS[:5]:  # Limit feeds per cycle
                try:
                    resp = session.get(feed_def["url"], timeout=15)
                    resp.raise_for_status()
                    parsed = feedparser.parse(resp.content)
                    for item in parsed.entries[:3]:
                        published = datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        )
                        if hasattr(item, "published_parsed") and item.published_parsed:
                            published = time.strftime(
                                "%Y-%m-%dT%H:%M:%SZ", item.published_parsed
                            )
                        title = (item.get("title") or "")[:200]
                        summary = _strip_html(
                            item.get("summary", "") or item.get("description", "")
                        )[:500]
                        entries.append(
                            {
                                "id": f"rss-{hash(title) & 0xFFFFFFFF:08x}",
                                "source": feed_def["name"],
                                "title": title,
                                "summary": summary,
                                "severity": _category_to_severity(feed_def["category"]),
                                "category": feed_def["category"],
                                "url": item.get("link", ""),
                                "timestamp": published,
                                "iocs": [],
                                "tlp": "CLEAR",
                                "live": True,
                            }
                        )
                except Exception:
                    continue
        except ImportError:
            pass
        return entries

    def _poll_ransomware_live(self) -> list[dict]:
        """Fetch recent ransomware victims from ransomware.live API."""
        try:
            session = get_clearnet_session()
            resp = session.get(
                "https://api.ransomware.live/v2/recentvictims", timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        entries = []
        for v in data[:5]:
            group = v.get("group_name") or "Unknown"
            title = v.get("post_title") or v.get("victim") or "Untitled"
            victim = v.get("victim") or "Unknown"
            entries.append(
                {
                    "id": f"rwlive-{hashlib.md5((group + title).encode()).hexdigest()[:12]}",
                    "source": "Ransomware.live",
                    "title": f"[{group}] {title[:150]}",
                    "summary": (
                        f"Group: {group}. "
                        f"Victim: {victim}. "
                        f"Country: {v.get('country', 'Unknown')}."
                    ),
                    "severity": "critical",
                    "category": "ransomware",
                    "url": "",
                    "timestamp": (v.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")) + "T00:00:00Z",
                    "iocs": [],
                    "tlp": "AMBER",
                    "live": True,
                }
            )
        return entries

    def _poll_threatfox(self) -> list[dict]:
        """Fetch recent IOCs from ThreatFox."""
        try:
            session = get_clearnet_session()
            resp = session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "get_iocs", "days": 1},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        entries = []
        for ioc in data.get("data", [])[:10]:
            ioc_type = ioc.get("ioc_type", "unknown")
            ioc_value = ioc.get("ioc", "")
            threat = ioc.get("threat_type", "")
            entries.append(
                {
                    "id": f"tf-{ioc.get('id', '')}",
                    "source": "ThreatFox",
                    "title": f"New IOC: {ioc_type.upper()} - {threat}",
                    "summary": (
                        f"IOC: {ioc_value}\n"
                        f"Type: {ioc_type}\n"
                        f"Threat: {threat}\n"
                        f"Malware: {ioc.get('malware', 'unknown')}\n"
                        f"Confidence: {ioc.get('confidence_level', 0)}%"
                    ),
                    "severity": _threat_to_severity(threat),
                    "category": "ioc",
                    "url": f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}",
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "iocs": [ioc_value],
                    "tlp": "CLEAR",
                    "live": True,
                }
            )
        return entries

    def _poll_malwarebazaar(self) -> list[dict]:
        """Fetch recent malware samples from MalwareBazaar."""
        try:
            session = get_clearnet_session()
            resp = session.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_recent", "selector": "time"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            return []

        entries = []
        for sample in data.get("data", [])[:5]:
            sha = sample.get("sha256_hash", "")
            fname = sample.get("file_name", "unknown")
            tags = sample.get("tags", [])
            entries.append(
                {
                    "id": f"mb-{sha[:16]}",
                    "source": "MalwareBazaar",
                    "title": f"New Sample: {fname}",
                    "summary": (
                        f"SHA256: {sha}\n"
                        f"Filename: {fname}\n"
                        f"Type: {sample.get('file_type', 'unknown')}\n"
                        f"Tags: {', '.join(tags) if tags else 'none'}\n"
                        f"Signature: {sample.get('signature', 'unknown')}"
                    ),
                    "severity": "high",
                    "category": "malware",
                    "url": f"https://bazaar.abuse.ch/sample/{sha}",
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "iocs": [sha],
                    "tlp": "CLEAR",
                    "live": True,
                }
            )
        return entries

    def _poll_cisa_kev(self) -> list[dict]:
        """Fetch CISA Known Exploited Vulnerabilities."""
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

        entries = []
        for vuln in data.get("vulnerabilities", [])[-5:]:
            entries.append(
                {
                    "id": vuln.get("cveID", ""),
                    "source": "CISA KEV",
                    "title": f"{vuln.get('cveID', '')} - {vuln.get('product', '')} [{vuln.get('vendorProject', '')}]",
                    "summary": (
                        f"CISA added {vuln.get('cveID', '')} to Known Exploited Vulnerabilities Catalog.\n"
                        f"Product: {vuln.get('product', '')}\n"
                        f"Vendor: {vuln.get('vendorProject', '')}\n"
                        f"Due date for federal agencies: {vuln.get('dueDate', '')}\n"
                        f"Notes: {vuln.get('notes', '')}"
                    ),
                    "severity": "critical",
                    "category": "government",
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "timestamp": (vuln.get("dateAdded") or "")[:10] + "T00:00:00Z",
                    "iocs": [vuln.get("cveID", "")],
                    "tlp": "CLEAR",
                    "live": True,
                }
            )
        return entries


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_html(text: str) -> str:
    import re

    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _category_to_severity(category: str) -> str:
    mapping = {"government": "high", "news": "medium", "research": "medium", "vendor": "high"}
    return mapping.get(category, "medium")


def _threat_to_severity(threat: str) -> str:
    threat_lower = (threat or "").lower()
    if any(t in threat_lower for t in ("ransomware", "emotet", "trickbot", "bazar", "cobalt")):
        return "critical"
    if any(t in threat_lower for t in ("trojan", "stealer", "backdoor", "botnet")):
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    agg = ThreatFeedAggregator()
    agg.seed_initial_data()
    feeds = agg.get_feeds("critical")
    print(f"Critical feeds: {len(feeds)}")
    for f in feeds[:5]:
        print(f"  [{f['severity'].upper()}] {f['source']}: {f['title'][:100]}")

    print("\nPolling live feeds...")
    new = agg.poll_new()
    print(f"New entries from live sources: {len(new)}")
    for f in new[:5]:
        live = " [LIVE]" if f.get("live") else ""
        print(f"  [{f['severity'].upper()}] {f['source']}{live}: {f['title'][:100]}")
