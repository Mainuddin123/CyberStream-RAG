
import json
from pathlib import Path

import requests

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = DATA_DIR / "threats.json"


def fetch_threats():
    response = requests.get(CISA_KEV_URL, timeout=30)
    response.raise_for_status()

    catalog = response.json()
    threats = catalog.get("vulnerabilities", [])

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(threats, indent=2),
        encoding="utf-8",
    )

    print("Catalog version:", catalog.get("catalogVersion", "Unknown"))
    print("Total vulnerabilities:", len(threats))
    print("Saved to:", OUTPUT_FILE)

    return threats


if __name__ == "__main__":
    threats = fetch_threats()

    print("\nFirst 5 vulnerabilities:")
    for threat in threats[:5]:
        print(threat.get("cveID"), "-", threat.get("vulnerabilityName"))
