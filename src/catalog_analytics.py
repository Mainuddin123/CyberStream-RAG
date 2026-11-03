
import json
import sqlite3
from collections import Counter
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "data" / "threats.db"


# These are keyword-based estimates, not official CISA categories.
VULNERABILITY_CATEGORIES = {
    "Remote Code Execution": [
        "remote code execution",
        "arbitrary code execution",
        "execute arbitrary code",
    ],
    "Information Disclosure": [
        "information disclosure",
        "disclose information",
        "exposure of sensitive information",
    ],
    "Privilege Escalation": [
        "privilege escalation",
        "elevation of privilege",
        "gain elevated privileges",
    ],
    "Denial of Service": [
        "denial of service",
        "denial-of-service",
        "dos vulnerability",
    ],
    "Authentication Bypass": [
        "authentication bypass",
        "bypass authentication",
        "improper authentication",
    ],
    "Cross-Site Scripting": [
        "cross-site scripting",
        "cross site scripting",
        "xss vulnerability",
    ],
    "SQL Injection": [
        "sql injection",
    ],
    "Memory Corruption": [
        "memory corruption",
        "buffer overflow",
        "heap overflow",
        "stack overflow",
        "use-after-free",
    ],
    "Directory Traversal": [
        "directory traversal",
        "path traversal",
    ],
    "Security Feature Bypass": [
        "security feature bypass",
        "protection mechanism failure",
    ],
}


def load_catalog_records():
    """Load all CISA vulnerability records from SQLite."""

    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Threat database not found: {DB_PATH}"
        )

    with sqlite3.connect(DB_PATH) as connection:
        rows = connection.execute(
            """
            SELECT cve_id, name, record_json
            FROM threats
            """
        ).fetchall()

    records = []

    for cve_id, name, record_json in rows:
        try:
            original = json.loads(record_json)
        except (TypeError, json.JSONDecodeError):
            original = {}

        description = original.get(
            "shortDescription", ""
        )

        records.append({
            "cve_id": cve_id,
            "name": name or "",
            "description": description or "",
        })

    return records


def classify_vulnerability(record):
    """
    Assign a category using transparent keyword matching.

    A record can match multiple categories.
    Unmatched records are classified as Other / Unclassified.
    """

    text = (
        f"{record.get('name', '')} "
        f"{record.get('description', '')}"
    ).lower()

    matched = []

    for category, keywords in VULNERABILITY_CATEGORIES.items():
        if any(keyword in text for keyword in keywords):
            matched.append(category)

    return matched or ["Other / Unclassified"]


def get_catalog_analytics():
    """Calculate catalog-wide vulnerability statistics."""

    records = load_catalog_records()

    category_counts = Counter()
    classified_cves = set()

    for record in records:
        categories = classify_vulnerability(record)

        for category in categories:
            category_counts[category] += 1
            classified_cves.add(record["cve_id"])

    total_records = len(records)

    rows = []

    for category, count in category_counts.most_common():
        percentage = (
            count / total_records * 100
            if total_records else 0
        )

        rows.append({
            "Vulnerability Type": category,
            "Record Count": count,
            "Percentage of Catalog": round(
                percentage, 2
            ),
        })

    dataframe = pd.DataFrame(rows)

    return {
        "total_records": total_records,
        "classified_records": len(classified_cves),
        "categories": dataframe,
        "classification_method": (
            "Keyword-based classification of vulnerability "
            "names and CISA short descriptions. A CVE can "
            "belong to multiple categories."
        ),
    }
