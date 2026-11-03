
import json
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "threats.db"


def initialize_database():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                cve_id TEXT PRIMARY KEY,
                name TEXT,
                vendor TEXT,
                product TEXT,
                date_added TEXT,
                date_updated TEXT,
                record_json TEXT NOT NULL
            )
        """)


def save_threats(threats):
    initialize_database()
    saved_count = 0

    with sqlite3.connect(DB_PATH) as conn:
        for threat in threats:
            cve_id = threat.get("cveID")
            if not cve_id:
                continue

            conn.execute("""
                INSERT INTO threats (
                    cve_id, name, vendor, product,
                    date_added, date_updated, record_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    name = excluded.name,
                    vendor = excluded.vendor,
                    product = excluded.product,
                    date_updated = excluded.date_updated,
                    record_json = excluded.record_json
            """, (
                cve_id,
                threat.get("vulnerabilityName"),
                threat.get("vendorProject"),
                threat.get("product"),
                threat.get("dateAdded"),
                threat.get("dateUpdated"),
                json.dumps(threat),
            ))
            saved_count += 1

    print(f"Saved {saved_count} threat records to {DB_PATH}")


if __name__ == "__main__":
    threats_file = DATA_DIR / "threats.json"
    threats = json.loads(threats_file.read_text(encoding="utf-8"))
    save_threats(threats)
