import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.config import BASE_DIR

DB_PATH = BASE_DIR / "phishguard.db"

def init_db() -> None:
    """Initialize the SQLite database with the required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_level TEXT NOT NULL,
            analysis_duration_ms REAL NOT NULL,
            shap_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_scan(
    url: str,
    verdict: str,
    confidence: float,
    risk_level: str,
    duration_ms: float,
    shap_features: list[dict[str, Any]]
) -> None:
    """Log an analysis result to the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO scans (timestamp, url, verdict, confidence, risk_level, analysis_duration_ms, shap_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                datetime.utcnow().isoformat() + "Z",
                url,
                verdict,
                confidence,
                risk_level,
                duration_ms,
                json.dumps(shap_features)
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to log scan to DB: {e}")

def get_stats() -> dict[str, Any]:
    """Retrieve aggregate statistics for the dashboard."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM scans")
        total_scans = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as phishing FROM scans WHERE verdict = 'phishing'")
        phishing_scans = cursor.fetchone()["phishing"]

        cursor.execute("SELECT COUNT(*) as legit FROM scans WHERE verdict = 'legitimate'")
        legit_scans = cursor.fetchone()["legit"]

        # Average confidence for phishing
        cursor.execute("SELECT AVG(confidence) as avg_conf FROM scans WHERE verdict = 'phishing'")
        avg_phishing_conf = cursor.fetchone()["avg_conf"] or 0.0

        # Recent scans
        cursor.execute("SELECT url, verdict, timestamp FROM scans ORDER BY id DESC LIMIT 10")
        recent_scans = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return {
            "total_scans": total_scans,
            "phishing_scans": phishing_scans,
            "legitimate_scans": legit_scans,
            "phishing_ratio": round(phishing_scans / total_scans * 100, 2) if total_scans > 0 else 0.0,
            "avg_phishing_confidence": round(avg_phishing_conf * 100, 2),
            "recent_scans": recent_scans
        }
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to get stats from DB: {e}")
        return {"error": str(e)}

# Init on module load
init_db()
