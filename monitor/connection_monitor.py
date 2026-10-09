"""
Sentinel Live Connection Monitor
Monitors real-time outbound host TCP/UDP network connections using psutil and DNS resolution.
Applies local privacy scoring and active user policy enforcement.
"""
import psutil
import socket
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.models import ConnectionEvent, ConnectionStatus, ActionDecision
from privacy_engine.detector import PrivacyDetector
from database.policy_store import PolicyStore

logger = logging.getLogger("sentinel.monitor")

class LiveConnectionMonitor:
    def __init__(self, detector: PrivacyDetector, policy_store: PolicyStore):
        self.detector = detector
        self.policy_store = policy_store
        self._dns_cache: Dict[str, str] = {}
        self._counts: Dict[str, int] = {}

    def _resolve_ip(self, ip: str) -> str:
        """Resolve remote IP to hostname with in-memory caching."""
        if not ip or ip in ["127.0.0.1", "0.0.0.0", "::1"]:
            return "localhost"
        if ip in self._dns_cache:
            return self._dns_cache[ip]
            
        try:
            # Set quick timeout for DNS resolution
            socket.setdefaulttimeout(0.3)
            hostname, _, _ = socket.gethostbyaddr(ip)
            self._dns_cache[ip] = hostname.lower()
            return self._dns_cache[ip]
        except Exception:
            # Fallback to IP address if reverse DNS fails
            self._dns_cache[ip] = ip
            return ip

    def poll_connections(self) -> List[ConnectionEvent]:
        """
        Poll active system network sockets and produce structured ConnectionEvents.
        """
        events: List[ConnectionEvent] = []
        seen_keys = set()

        try:
            net_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.warning(f"Could not access low-level socket connections: {e}")
            return []

        for conn in net_conns:
            # Filter for outbound established or SYN_SENT connections with remote address
            if not conn.raddr or conn.status not in ["ESTABLISHED", "SYN_SENT", "TIME_WAIT"]:
                continue

            r_ip, r_port = conn.raddr.ip, conn.raddr.port
            # Skip loopback and private LAN
            if r_ip.startswith("127.") or r_ip.startswith("10.") or r_ip.startswith("192.168."):
                continue

            # Identify application process
            app_name = "unknown"
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    app_name = proc.name().replace(".exe", "").lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    app_name = "system"

            domain = self._resolve_ip(r_ip)
            key = f"{app_name}:{domain}"
            
            # Update frequency counter
            self._counts[key] = self._counts.get(key, 0) + 1
            freq = self._counts[key]

            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Check policy store
            rec = self.policy_store.get_decision(domain, app_name)
            status = ConnectionStatus.ACTIVE
            if rec:
                if rec.decision == ActionDecision.BLOCK:
                    status = ConnectionStatus.BLOCKED
                else:
                    status = ConnectionStatus.ALLOWED

            ev = self.detector.create_event(
                application=app_name,
                domain=domain,
                ip=r_ip,
                port=r_port,
                connection_count=freq,
                status=status
            )
            events.append(ev)

        return events
