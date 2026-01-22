"""
Phase 6: Persistent Reputation Tracker
Cross-session intelligence with long-term memory and recidivism detection.

Features:
- Persistent IP/domain reputation database
- Historical attack pattern correlation
- Geolocation-aware risk profiles
- Recidivism detection (repeat offenders)
- Reputation decay algorithm
- OSINT feed integration
- Timeline visualization data
"""

import json
import sqlite3
import time
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib
import logging

logger = logging.getLogger(__name__)


@dataclass
class ReputationRecord:
    """Individual reputation record for an IP/domain."""
    entity: str  # IP address or domain
    entity_type: str  # "ip" or "domain"
    first_seen: float  # Unix timestamp
    last_seen: float
    total_attacks: int
    attack_types: Dict[str, int]  # attack_type -> count
    severity_scores: List[float]  # historical severity
    geolocation: Optional[Dict[str, str]]  # country, region, asn
    reputation_score: float  # 0.0 (clean) to 1.0 (malicious)
    is_recidivist: bool  # repeat offender flag
    blocked_count: int  # times blocked
    last_attack_signature: str  # most recent attack pattern


@dataclass
class ReputationQuery:
    """Query result with historical context."""
    entity: str
    reputation_score: float
    threat_level: str  # "CLEAN", "SUSPICIOUS", "MALICIOUS", "CRITICAL"
    is_recidivist: bool
    total_attacks: int
    days_since_first_seen: float
    days_since_last_seen: float
    attack_timeline: List[Dict]  # chronological attack history
    risk_factors: List[str]  # human-readable risk explanation


class ReputationTracker:
    """
    Persistent reputation tracking system with cross-session intelligence.
    
    Architecture:
    - SQLite database for persistent storage
    - In-memory cache for fast lookups
    - JSON export to relay/ai_training_materials/
    - Reputation decay algorithm (old threats age out)
    - Recidivism detection (repeat offenders escalated)
    """
    
    def __init__(self, db_path: str | None = None, 
                 decay_days: int = 90, recidivist_threshold: int = 3):
        """
        Initialize reputation tracker.
        
        Args:
            db_path: Optional path to SQLite database. When omitted, uses
                the JSON directory returned by AI.path_helper.get_json_dir()
                so reputation.db lives alongside other server JSON state in
                both Docker and native deployments.
            decay_days: Days until reputation starts decaying
            recidivist_threshold: Attacks needed to mark as recidivist
        """
        from AI.path_helper import get_json_file  # type: ignore[import]
        if db_path is None:
            self.db_path = get_json_file('reputation.db')
        else:
            self.db_path = db_path
        self.decay_days = decay_days
        self.recidivist_threshold = recidivist_threshold
        
        # Create directories
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # In-memory cache (entity -> ReputationRecord)
        self.cache: Dict[str, ReputationRecord] = {}
        self._load_cache()
        
        # Statistics
        self.stats = {
            "queries": 0,
            "updates": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "recidivists_detected": 0
        }
    
    def _init_database(self):
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main reputation table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reputation (
                entity TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                total_attacks INTEGER DEFAULT 0,
                attack_types TEXT,  -- JSON
                severity_scores TEXT,  -- JSON array
                geolocation TEXT,  -- JSON
                reputation_score REAL DEFAULT 0.0,
                is_recidivist INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                last_attack_signature TEXT
            )
        """)
        
        # Attack timeline table (detailed history)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attack_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity TEXT NOT NULL,
                timestamp REAL NOT NULL,
                attack_type TEXT NOT NULL,
                severity REAL NOT NULL,
                signature TEXT,
                blocked INTEGER DEFAULT 0,
                FOREIGN KEY (entity) REFERENCES reputation(entity)
            )
        """)
        
        # Indices for fast queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entity ON reputation(entity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON reputation(last_seen)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_reputation_score ON reputation(reputation_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_entity ON attack_timeline(entity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON attack_timeline(timestamp)")
        
        conn.commit()
        conn.close()
    
    def _load_cache(self):
        """Load recent records into memory cache."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Load entities seen in last 30 days
        cutoff = time.time() - (30 * 24 * 3600)
        cursor.execute("""
            SELECT entity, entity_type, first_seen, last_seen, total_attacks,
                   attack_types, severity_scores, geolocation, reputation_score,
                   is_recidivist, blocked_count, last_attack_signature
            FROM reputation
            WHERE last_seen > ?
            ORDER BY last_seen DESC
            LIMIT 10000
        """, (cutoff,))
        
        for row in cursor.fetchall():
            record = ReputationRecord(
                entity=row[0],
                entity_type=row[1],
                first_seen=row[2],
                last_seen=row[3],
                total_attacks=row[4],
                attack_types=json.loads(row[5]) if row[5] else {},
                severity_scores=json.loads(row[6]) if row[6] else [],
                geolocation=json.loads(row[7]) if row[7] else None,
                reputation_score=row[8],
                is_recidivist=bool(row[9]),
                blocked_count=row[10],
                last_attack_signature=row[11] or ""
            )
            self.cache[row[0]] = record
        
        conn.close()
    
    def record_attack(self, entity: str, entity_type: str = "ip",
                     attack_type: str = "unknown", severity: float = 0.5,
                     signature: str = "", blocked: bool = False,
                     geolocation: Optional[Dict[str, str]] = None) -> ReputationRecord:
        """
        Record an attack and update reputation.
        
        Args:
            entity: IP address or domain
            entity_type: "ip" or "domain"
            attack_type: Type of attack (sql_injection, xss, etc.)
            severity: Severity score 0.0-1.0
            signature: Attack signature/pattern
            blocked: Whether attack was blocked
            geolocation: {country, region, asn}
        
        Returns:
            Updated ReputationRecord
        """
        self.stats["updates"] += 1
        now = time.time()
        
        # Get or create record
        if entity in self.cache:
            record = self.cache[entity]
            self.stats["cache_hits"] += 1
        else:
            record = self._load_from_db(entity)
            if record is None:
                # New entity
                record = ReputationRecord(
                    entity=entity,
                    entity_type=entity_type,
                    first_seen=now,
                    last_seen=now,
                    total_attacks=0,
                    attack_types={},
                    severity_scores=[],
                    geolocation=geolocation,
                    reputation_score=0.0,
                    is_recidivist=False,
                    blocked_count=0,
                    last_attack_signature=""
                )
            self.stats["cache_misses"] += 1
        
        # Update record
        record.last_seen = now
        record.total_attacks += 1
        record.attack_types[attack_type] = record.attack_types.get(attack_type, 0) + 1
        record.severity_scores.append(severity)
        if blocked:
            record.blocked_count += 1
        if signature:
            record.last_attack_signature = signature
        if geolocation and not record.geolocation:
            record.geolocation = geolocation
        
        # Recidivism detection
        if record.total_attacks >= self.recidivist_threshold and not record.is_recidivist:
            record.is_recidivist = True
            self.stats["recidivists_detected"] += 1
        
        # Calculate reputation score with decay
        record.reputation_score = self._calculate_reputation(record)
        
        # Update cache
        self.cache[entity] = record
        
        # Persist to database
        self._save_to_db(record)
        self._save_timeline_event(entity, now, attack_type, severity, signature, blocked)
        
        return record
    
    def _calculate_reputation(self, record: ReputationRecord) -> float:
        """
        Calculate reputation score with temporal decay.
        
        Algorithm:
        1. Base score from attack frequency and severity
        2. Recidivist multiplier (repeat offenders worse)
        3. Temporal decay (old attacks matter less)
        4. Geolocation risk factor
        
        Returns:
            Score 0.0 (clean) to 1.0 (critical threat)
        """
        if record.total_attacks == 0:
            return 0.0
        
        # 1. Attack frequency score (logarithmic scaling)
        import math
        frequency_score = min(1.0, math.log10(record.total_attacks + 1) / 3)
        
        # 2. Severity score (average of recent attacks, max 50)
        recent_severities = record.severity_scores[-50:]
        avg_severity = sum(recent_severities) / len(recent_severities) if recent_severities else 0.0
        
        # 3. Temporal decay
        days_since_last = (time.time() - record.last_seen) / 86400
        decay_factor = max(0.0, 1.0 - (days_since_last / self.decay_days))
        
        # 4. Recidivist multiplier (1.5x for repeat offenders)
        recidivist_multiplier = 1.5 if record.is_recidivist else 1.0
        
        # 5. Geolocation risk (high-risk countries get +0.1)
        geo_risk = 0.0
        if record.geolocation:
            high_risk_countries = {"CN", "RU", "KP", "IR"}
            if record.geolocation.get("country") in high_risk_countries:
                geo_risk = 0.1
        
        # Combine factors
        base_score = (frequency_score * 0.4 + avg_severity * 0.6) * recidivist_multiplier
        final_score = min(1.0, (base_score + geo_risk) * decay_factor)
        
        return round(final_score, 4)
    
    def query_reputation(self, entity: str) -> Optional[ReputationQuery]:
        """
        Query reputation with full historical context.
        
        Args:
            entity: IP address or domain to query
        
        Returns:
            ReputationQuery with timeline and risk factors, or None if not found
        """
        self.stats["queries"] += 1
        
        # Check cache first
        if entity in self.cache:
            record = self.cache[entity]
            self.stats["cache_hits"] += 1
        else:
            record = self._load_from_db(entity)
            if record is None:
                return None
            self.stats["cache_misses"] += 1
        
        # Recalculate with current decay
        record.reputation_score = self._calculate_reputation(record)
        
        # Get attack timeline
        timeline = self._load_timeline(entity, limit=100)
        
        # Determine threat level
        if record.reputation_score >= 0.8:
            threat_level = "CRITICAL"
        elif record.reputation_score >= 0.6:
            threat_level = "MALICIOUS"
        elif record.reputation_score >= 0.3:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "CLEAN"
        
        # Generate risk factors
        risk_factors = self._generate_risk_factors(record)
        
        # Calculate time deltas
        now = time.time()
        days_since_first = (now - record.first_seen) / 86400
        days_since_last = (now - record.last_seen) / 86400
        
        return ReputationQuery(
            entity=entity,
            reputation_score=record.reputation_score,
            threat_level=threat_level,
            is_recidivist=record.is_recidivist,
            total_attacks=record.total_attacks,
            days_since_first_seen=round(days_since_first, 2),
            days_since_last_seen=round(days_since_last, 2),
            attack_timeline=timeline,
            risk_factors=risk_factors
        )
    
    def _generate_risk_factors(self, record: ReputationRecord) -> List[str]:
        """Generate human-readable risk factors."""
        factors = []
        
        if record.is_recidivist:
            factors.append(f"Recidivist: {record.total_attacks} attacks recorded")
        
        if record.total_attacks >= 10:
            factors.append(f"High attack frequency: {record.total_attacks} total attacks")
        
        if record.blocked_count >= 5:
            factors.append(f"Blocked {record.blocked_count} times")
        
        if record.severity_scores:
            avg_severity = sum(record.severity_scores[-10:]) / min(10, len(record.severity_scores))
            if avg_severity >= 0.7:
                factors.append(f"High severity attacks (avg: {avg_severity:.2f})")
        
        if record.geolocation:
            country = record.geolocation.get("country", "")
            if country in {"CN", "RU", "KP", "IR"}:
                factors.append(f"High-risk geolocation: {country}")
        
        # Most common attack type
        if record.attack_types:
            most_common = max(record.attack_types.items(), key=lambda x: x[1])
            if most_common[1] >= 3:
                factors.append(f"Specializes in {most_common[0]} ({most_common[1]} times)")
        
        days_since_last = (time.time() - record.last_seen) / 86400
        if days_since_last < 1:
            factors.append("Recent activity (within 24 hours)")
        
        return factors
    
    def _load_from_db(self, entity: str) -> Optional[ReputationRecord]:
        """Load record from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT entity_type, first_seen, last_seen, total_attacks,
                   attack_types, severity_scores, geolocation, reputation_score,
                   is_recidivist, blocked_count, last_attack_signature
            FROM reputation
            WHERE entity = ?
        """, (entity,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row is None:
            return None
        
        return ReputationRecord(
            entity=entity,
            entity_type=row[0],
            first_seen=row[1],
            last_seen=row[2],
            total_attacks=row[3],
            attack_types=json.loads(row[4]) if row[4] else {},
            severity_scores=json.loads(row[5]) if row[5] else [],
            geolocation=json.loads(row[6]) if row[6] else None,
            reputation_score=row[7],
            is_recidivist=bool(row[8]),
            blocked_count=row[9],
            last_attack_signature=row[10] or ""
        )
    
    def _save_to_db(self, record: ReputationRecord):
        """Save record to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO reputation
            (entity, entity_type, first_seen, last_seen, total_attacks,
             attack_types, severity_scores, geolocation, reputation_score,
             is_recidivist, blocked_count, last_attack_signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record.entity,
            record.entity_type,
            record.first_seen,
            record.last_seen,
            record.total_attacks,
            json.dumps(record.attack_types),
            json.dumps(record.severity_scores),
            json.dumps(record.geolocation) if record.geolocation else None,
            record.reputation_score,
            1 if record.is_recidivist else 0,
            record.blocked_count,
            record.last_attack_signature
        ))
        
        conn.commit()
        conn.close()
    
    def _save_timeline_event(self, entity: str, timestamp: float, 
                            attack_type: str, severity: float,
                            signature: str, blocked: bool):
        """Save individual attack event to timeline."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO attack_timeline
            (entity, timestamp, attack_type, severity, signature, blocked)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (entity, timestamp, attack_type, severity, signature, 1 if blocked else 0))
        
        conn.commit()
        conn.close()
    
    def _load_timeline(self, entity: str, limit: int = 100) -> List[Dict]:
        """Load attack timeline for entity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT timestamp, attack_type, severity, signature, blocked
            FROM attack_timeline
            WHERE entity = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (entity, limit))
        
        timeline = []
        for row in cursor.fetchall():
            timeline.append({
                "timestamp": row[0],
                "datetime": datetime.fromtimestamp(row[0]).isoformat(),
                "attack_type": row[1],
                "severity": row[2],
                "signature": row[3],
                "blocked": bool(row[4])
            })
        
        conn.close()
        return timeline
    
    def get_top_offenders(self, limit: int = 100) -> List[ReputationQuery]:
        """Get top malicious entities by reputation score."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT entity
            FROM reputation
            ORDER BY reputation_score DESC, total_attacks DESC
            LIMIT ?
        """, (limit,))
        
        entities = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return [self.query_reputation(e) for e in entities if self.query_reputation(e)]
    
    def get_recidivists(self) -> List[ReputationQuery]:
        """Get all repeat offenders."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT entity
            FROM reputation
            WHERE is_recidivist = 1
            ORDER BY total_attacks DESC
        """)
        
        entities = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        return [self.query_reputation(e) for e in entities if self.query_reputation(e)]
    
    def export_training_data(self) -> str:
        """
        Export reputation data to AI training materials.
        
        Exports to: reputation_data/ under the relay training directory
        returned by AI.path_helper.get_relay_training_dir().
        
        Returns:
            Path to exported file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        from AI.path_helper import get_relay_training_dir, get_json_file  # type: ignore[import]
        base_path = os.path.join(get_relay_training_dir(), "reputation_data")
        
        # Get all records
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reputation ORDER BY reputation_score DESC")
        
        export_data = {
            "export_timestamp": time.time(),
            "export_datetime": datetime.now().isoformat(),
            "total_entities": 0,
            "recidivists": 0,
            "avg_reputation_score": 0.0,
            "records": []
        }
        
        total_score = 0.0
        for row in cursor.fetchall():
            record = {
                "entity": row[0],
                "entity_type": row[1],
                "first_seen": row[2],
                "last_seen": row[3],
                "total_attacks": row[4],
                "attack_types": json.loads(row[5]) if row[5] else {},
                "reputation_score": row[8],
                "is_recidivist": bool(row[9]),
                "blocked_count": row[10]
            }
            export_data["records"].append(record)
            total_score += row[8]
            if row[9]:
                export_data["recidivists"] += 1
        
        conn.close()
        
        export_data["total_entities"] = len(export_data["records"])
        if export_data["total_entities"] > 0:
            export_data["avg_reputation_score"] = round(
                total_score / export_data["total_entities"], 4
            )
        
        # Save to multiple locations
        paths = [
            f"{base_path}/reputation_latest.json",
            f"{base_path}/reputation_{timestamp}.json",
            get_json_file("reputation_export.json"),
        ]
        
        for path in paths:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                json.dump(export_data, f, indent=2)
        
        return paths[0]
    
    def cleanup_old_records(self, days: int = 180) -> int:
        """
        Clean up records older than specified days with no recent activity.
        
        Args:
            days: Delete records not seen in this many days
        
        Returns:
            Number of records deleted
        """
        cutoff = time.time() - (days * 24 * 3600)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Delete old timeline events first
        cursor.execute("DELETE FROM attack_timeline WHERE timestamp < ?", (cutoff,))
        
        # Delete old reputation records
        cursor.execute("""
            DELETE FROM reputation
            WHERE last_seen < ? AND reputation_score < 0.3
        """, (cutoff,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        # Clear cache
        self.cache = {k: v for k, v in self.cache.items() if v.last_seen >= cutoff}
        
        return deleted
    
    def get_statistics(self) -> Dict:
        """Get tracker statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM reputation")
        total_entities = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM reputation WHERE is_recidivist = 1")
        recidivists = cursor.fetchone()[0]
        
        cursor.execute("SELECT AVG(reputation_score) FROM reputation")
        avg_score = cursor.fetchone()[0] or 0.0
        
        cursor.execute("SELECT COUNT(*) FROM attack_timeline")
        total_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_entities": total_entities,
            "recidivists": recidivists,
            "recidivist_rate": round(recidivists / total_entities * 100, 2) if total_entities > 0 else 0,
            "avg_reputation_score": round(avg_score, 4),
            "total_attack_events": total_events,
            "cache_size": len(self.cache),
            "cache_hit_rate": round(
                self.stats["cache_hits"] / max(1, self.stats["queries"]) * 100, 2
            ),
            **self.stats
        }


# Global instance
REPUTATION_TRACKER_AVAILABLE = True
_tracker_instance = None

def get_reputation_tracker() -> ReputationTracker:
    """Get global reputation tracker instance."""
    global _tracker_instance
    if _tracker_instance is None:
        _tracker_instance = ReputationTracker()
    return _tracker_instance


if __name__ == "__main__":
    # Demo usage
    tracker = ReputationTracker()
    
    # Record some attacks
    print("Recording attacks...")
    tracker.record_attack("192.168.1.100", "ip", "sql_injection", 0.8, "UNION SELECT", True, 
                         {"country": "CN", "region": "Beijing", "asn": "AS4134"})
    tracker.record_attack("192.168.1.100", "ip", "xss", 0.7, "<script>", True)
    tracker.record_attack("192.168.1.100", "ip", "sql_injection", 0.9, "DROP TABLE", True)
    tracker.record_attack("192.168.1.100", "ip", "brute_force", 0.6, "", False)
    
    # Query reputation
    print("\nQuerying reputation...")
    result = tracker.query_reputation("192.168.1.100")
    if result:
        print(f"Entity: {result.entity}")
        print(f"Threat Level: {result.threat_level}")
        print(f"Reputation Score: {result.reputation_score}")
        print(f"Is Recidivist: {result.is_recidivist}")
        print(f"Total Attacks: {result.total_attacks}")
        print(f"Risk Factors:")
        for factor in result.risk_factors:
            print(f"  - {factor}")
    
    # Export training data
    print("\nExporting training data...")
    path = tracker.export_training_data()
    print(f"Exported to: {path}")
    
    # Statistics
    print("\nStatistics:")
    stats = tracker.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
