"""
Sentinel SQLite Policy Store
Manages persistent user decisions (block, allow, always_allow, ask_later),
blocking rules, and historical network telemetry events.
"""
import sqlite3
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from backend.models import ActionDecision, ConnectionStatus, ConnectionEvent, UserDecisionRecord

class PolicyStore:
    def __init__(self, db_path: str = "sentinel_data.db"):
        self.db_path = db_path
        self._shared_conn = None
        if db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database tables for user decisions and traffic history."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Table 1: User Policy Rules
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                domain TEXT NOT NULL,
                application TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (domain, application)
            )
        """)

        # Table 2: Connection Event History
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                application TEXT NOT NULL,
                domain TEXT NOT NULL,
                ip TEXT,
                port INTEGER,
                protocol TEXT,
                timestamp TEXT NOT NULL,
                connection_count INTEGER NOT NULL,
                category TEXT NOT NULL,
                known_tracker INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                vendor TEXT,
                details TEXT
            )
        """)

        # Index for fast domain query
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policies_domain ON policies(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_app ON events(application)")
        conn.commit()
        if self._shared_conn is None:
            conn.close()

    def save_decision(
        self,
        domain: str,
        application: str,
        decision: ActionDecision,
        reason: Optional[str] = None
    ) -> UserDecisionRecord:
        """Save or update a user decision rule."""
        clean_dom = domain.lower().strip()
        clean_app = application.lower().strip()
        now = datetime.now(timezone.utc).isoformat()
        
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO policies (domain, application, decision, reason, created_at, active)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(domain, application) DO UPDATE SET
                decision = excluded.decision,
                reason = excluded.reason,
                created_at = excluded.created_at,
                active = 1
        """, (clean_dom, clean_app, decision.value, reason, now))
        conn.commit()
        if self._shared_conn is None:
            conn.close()

        return UserDecisionRecord(
            domain=clean_dom,
            application=clean_app,
            decision=decision,
            timestamp=now,
            reason=reason,
            active=True
        )

    def get_decision(self, domain: str, application: str) -> Optional[UserDecisionRecord]:
        """
        Check if a policy exists for this domain (either app-specific or global '*').
        """
        clean_dom = domain.lower().strip()
        clean_app = application.lower().strip()
        
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT domain, application, decision, reason, created_at, active
            FROM policies
            WHERE domain = ? AND (application = ? OR application = '*') AND active = 1
            ORDER BY CASE WHEN application = ? THEN 0 ELSE 1 END
            LIMIT 1
        """, (clean_dom, clean_app, clean_app))
        row = cursor.fetchone()
        res = None
        if row:
            res = UserDecisionRecord(
                domain=row["domain"],
                application=row["application"],
                decision=ActionDecision(row["decision"]),
                timestamp=row["created_at"],
                reason=row["reason"],
                active=bool(row["active"])
            )
        if self._shared_conn is None:
            conn.close()
        return res

    def list_active_rules(self) -> List[UserDecisionRecord]:
        """Return all active policy rules."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT domain, application, decision, reason, created_at, active
            FROM policies
            WHERE active = 1
            ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()
        rules = [
            UserDecisionRecord(
                domain=r["domain"],
                application=r["application"],
                decision=ActionDecision(r["decision"]),
                timestamp=r["created_at"],
                reason=r["reason"],
                active=bool(r["active"])
            )
            for r in rows
        ]
        if self._shared_conn is None:
            conn.close()
        return rules

    def delete_rule(self, domain: str, application: str) -> bool:
        """Remove a rule by deleting it."""
        clean_dom = domain.lower().strip()
        clean_app = application.lower().strip()
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM policies
            WHERE domain = ? AND application = ?
        """, (clean_dom, clean_app))
        conn.commit()
        count = cursor.rowcount
        if self._shared_conn is None:
            conn.close()
        return count > 0

    def record_events(self, events: List[ConnectionEvent]):
        """Record batch of events to SQLite."""
        if not events:
            return
        conn = self._get_connection()
        cursor = conn.cursor()
        for ev in events:
            cursor.execute("""
                INSERT OR REPLACE INTO events (
                    id, application, domain, ip, port, protocol, timestamp,
                    connection_count, category, known_tracker, risk_level,
                    risk_score, status, vendor, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev.id,
                ev.application,
                ev.domain,
                ev.ip,
                ev.port,
                ev.protocol,
                ev.timestamp,
                ev.connection_count,
                ev.category.value,
                1 if ev.known_tracker else 0,
                ev.risk_level.value,
                ev.risk_score,
                ev.status.value,
                ev.vendor,
                ev.details
            ))
        conn.commit()
        if self._shared_conn is None:
            conn.close()

    def get_top_offenders(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get applications contacting the most trackers or third parties."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                application,
                COUNT(*) as total_conns,
                SUM(CASE WHEN known_tracker = 1 THEN 1 ELSE 0 END) as tracker_count,
                SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk_count
            FROM events
            GROUP BY application
            ORDER BY tracker_count DESC, total_conns DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        offenders = [dict(r) for r in rows]
        if self._shared_conn is None:
            conn.close()
        return offenders

    def clear_all(self):
        """Wipe database for fresh test run."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM policies")
        cursor.execute("DELETE FROM events")
        conn.commit()
        if self._shared_conn is None:
            conn.close()
