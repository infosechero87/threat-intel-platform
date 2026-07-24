"""Tor / SOCKS5 proxy configuration for dark web modules.

Reads from environment:
  TOR_ENABLED  - "true"/"false" (default: true)
  TOR_PROXY    - SOCKS5 proxy URL (default: socks5://127.0.0.1:9050)
  TOR_CONTROL  - ControlPort (default: 9051)

Provides a shared requests.Session pre-configured for Tor.
Falls back gracefully to direct (clearnet) connections if Tor is unavailable.
"""
import os
import socket
import logging

logger = logging.getLogger(__name__)

TOR_ENABLED = os.environ.get("TOR_ENABLED", "true").lower() == "true"
TOR_PROXY = os.environ.get("TOR_PROXY", "socks5://127.0.0.1:9050")
TOR_CONTROL = int(os.environ.get("TOR_CONTROL", "9051"))
USER_AGENT = "ThreatIntelPlatform/2.0 (cyber-threat-intelligence; +https://github.com/infosechero87/threat-intel-platform)"


def _check_tor_available(timeout: float = 3.0) -> bool:
    """Verify Tor SOCKS5 port is listening."""
    if not TOR_ENABLED:
        return False
    try:
        host, port = TOR_PROXY.replace("socks5://", "").split(":")
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


TOR_AVAILABLE = _check_tor_available()


def get_session(use_tor: bool = None) -> "requests.Session":
    """Return a requests Session optionally routed through Tor.

    Args:
        use_tor: Override TOR_ENABLED. None = use global setting.

    Returns a requests.Session ready for use.
    """
    import requests

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    should_use_tor = TOR_ENABLED if use_tor is None else use_tor

    if should_use_tor and TOR_AVAILABLE:
        session.proxies = {
            "http": TOR_PROXY,
            "https": TOR_PROXY,
        }
        session.trust_env = False  # don't use system proxy settings

    return session


def get_clearnet_session() -> "requests.Session":
    """Return a session without Tor (for clearnet APIs)."""
    return get_session(use_tor=False)


def get_tor_session() -> "requests.Session":
    """Return a session routed through Tor, or raise if unavailable."""
    if not TOR_AVAILABLE:
        raise RuntimeError("Tor is not available. Start tor service and set TOR_PROXY if needed.")
    return get_session(use_tor=True)


def status() -> dict:
    """Return current Tor configuration status."""
    return {
        "tor_enabled": TOR_ENABLED,
        "tor_available": TOR_AVAILABLE,
        "tor_proxy": TOR_PROXY,
        "tor_control": TOR_CONTROL,
    }
