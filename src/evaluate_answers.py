import re
import json
import csv
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "data"
OUTPUT_FILE = RESULTS_DIR / "answer_quality_results.csv"

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def evaluate_answer(question, answer, retrieved_cves):
    answer = answer or ""
    retrieved_set = {cve.upper() for cve in retrieved_cves}
    cited_cves = set(CVE_PATTERN.findall(answer.upper()))

    valid_citations = cited_cves & retrieved_set
    unsupported_citations = cited_cves - retrieved_set

    citation_correctness = (
        len(valid_citations) / len(cited_cves)
        if cited_cves else 0.0
    )

    answer_present = bool(answer.strip())
    has_evidence_language = any(
        phrase in answer.lower()
        for phrase in (
            "based on",
            "according to",
            "the evidence",
            "cve-",
            "vulnerability",
        )
    )

    return {
        "question": question,
        "answer_present": int(answer_present),
        "answer_length": len(answer),
        "contains_evidence_language": int(has_evidence_language),
        "cited_cves": "; ".join(sorted(cited_cves)),
        "valid_retrieved_citations": "; ".join(sorted(valid_citations)),
        "unsupported_citations": "; ".join(sorted(unsupported_citations)),
        "citation_correctness": round(citation_correctness, 4),
        "citation_check": (
            "PASS" if cited_cves and not unsupported_citations
            else "REVIEW"
        ),
    }


def main():
    print("CyberStream RAG - Answer Quality Evaluator")
    print("Paste the answer and finish with a line containing END.")

    rows = []

    while True:
        question = input("\nQuestion (or 'exit'): ").strip()

        if question.lower() in {"exit", "quit"}:
            break

        if not question:
            print("Enter a question.")
            continue

        print("Paste the generated answer, then type END on a new line.")
        answer_lines = []

        while True:
            line = input()
            if line.strip() == "END":
                break
            answer_lines.append(line)

        raw_cves = input(
            "Enter retrieved CVE IDs separated by commas: "
        ).strip()

        retrieved_cves = [
            item.strip().upper()
            for item in raw_cves.split(",")
            if item.strip()
        ]

        result = evaluate_answer(
            question,
            "\n".join(answer_lines),
            retrieved_cves,
        )
        rows.append(result)

        print("\nEvaluation:")
        for key, value in result.items():
            print(f"{key}: {value}")

    if rows:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

        fieldnames = list(rows[0].keys())
        write_header = not OUTPUT_FILE.exists()

        with OUTPUT_FILE.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        print(f"\nSaved answer-quality results to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
