
import csv
import re
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_ROOT / "data" / "answer_quality_results.csv"

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)

# Fixed column order prevents schema/order inconsistencies.
FIELDNAMES = [
    "timestamp_utc",
    "question",
    "answer_present",
    "answer_length",
    "contains_evidence_language",
    "cited_cves",
    "valid_retrieved_citations",
    "unsupported_citations",
    "citation_correctness",
    "citation_check",
]


def evaluate_answer(question, answer, evidence):
    """Check whether CVE citations belong to retrieved evidence."""
    answer = answer or ""
    question = str(question or "").strip()

    retrieved_ids = {
        str(item.get("cve_id", "")).strip().upper()
        for item in evidence
        if item.get("cve_id")
    }

    cited_ids = {
        cve.upper()
        for cve in CVE_PATTERN.findall(answer)
    }

    valid_ids = cited_ids & retrieved_ids
    unsupported_ids = cited_ids - retrieved_ids

    citation_correctness = (
        len(valid_ids) / len(cited_ids)
        if cited_ids
        else 0.0
    )

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "answer_present": int(bool(answer.strip())),
        "answer_length": len(answer),
        "contains_evidence_language": int(
            any(
                phrase in answer.lower()
                for phrase in (
                    "based on the evidence",
                    "provided cisa evidence",
                    "supplied cisa evidence",
                    "retrieved cisa evidence",
                )
            )
        ),
        "cited_cves": "; ".join(sorted(cited_ids)),
        "valid_retrieved_citations": "; ".join(sorted(valid_ids)),
        "unsupported_citations": "; ".join(sorted(unsupported_ids)),
        "citation_correctness": round(citation_correctness, 4),
        "citation_check": (
            "PASS"
            if cited_ids and not unsupported_ids
            else "REVIEW"
        ),
    }


def save_result(result):
    """Append a result using a stable CSV schema."""
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Write only known columns in a consistent order.
    row = {
        field: result.get(field, "")
        for field in FIELDNAMES
    }

    write_header = (
        not OUTPUT_FILE.exists()
        or OUTPUT_FILE.stat().st_size == 0
    )

    with OUTPUT_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=FIELDNAMES,
            extrasaction="ignore",
        )

        if write_header:
            writer.writeheader()

        writer.writerow(row)


if __name__ == "__main__":
    print("Import this module from src.rag to evaluate answers.")
