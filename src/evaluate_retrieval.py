
import csv
import json
import math
from pathlib import Path

from src.search import search_threats

# --------------------------------------------------
# Configuration
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVALUATION_FILE = (
    PROJECT_ROOT / "data" / "evaluation_questions.json"
)

RESULTS_FILE = (
    PROJECT_ROOT / "data" / "retrieval_evaluation_results.csv"
)

TOP_K = 5


# --------------------------------------------------
# Metric calculations
# --------------------------------------------------

def normalize_ids(ids):
    return {
        str(item).strip().upper()
        for item in ids
        if item
    }


def hit_at_k(ranked_ids, relevant_ids, k):
    ranked = normalize_ids(ranked_ids[:k])
    relevant = normalize_ids(relevant_ids)

    return int(bool(ranked & relevant))


def precision_at_k(ranked_ids, relevant_ids, k):
    if k <= 0:
        return 0.0

    ranked = normalize_ids(ranked_ids[:k])
    relevant = normalize_ids(relevant_ids)

    return len(ranked & relevant) / k


def recall_at_k(ranked_ids, relevant_ids, k):
    relevant = normalize_ids(relevant_ids)

    if not relevant:
        return 0.0

    ranked = normalize_ids(ranked_ids[:k])

    return len(ranked & relevant) / len(relevant)


def reciprocal_rank(ranked_ids, relevant_ids):
    relevant = normalize_ids(relevant_ids)

    for rank, cve_id in enumerate(ranked_ids, start=1):
        if str(cve_id).strip().upper() in relevant:
            return 1.0 / rank

    return 0.0


def dcg_at_k(ranked_ids, relevant_ids, k):
    relevant = normalize_ids(relevant_ids)
    score = 0.0

    for rank, cve_id in enumerate(ranked_ids[:k], start=1):
        if str(cve_id).strip().upper() in relevant:
            score += 1.0 / math.log2(rank + 1)

    return score


def ndcg_at_k(ranked_ids, relevant_ids, k):
    relevant = normalize_ids(relevant_ids)

    if not relevant or k <= 0:
        return 0.0

    ideal_count = min(len(relevant), k)

    ideal_dcg = sum(
        1.0 / math.log2(rank + 1)
        for rank in range(1, ideal_count + 1)
    )

    if ideal_dcg == 0:
        return 0.0

    actual_dcg = dcg_at_k(
        ranked_ids,
        relevant,
        k,
    )

    return actual_dcg / ideal_dcg


# --------------------------------------------------
# Main evaluation
# --------------------------------------------------

def main():

    if not EVALUATION_FILE.exists():
        print("Evaluation dataset not found.")
        return

    with EVALUATION_FILE.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        test_cases = json.load(file)

    if not test_cases:
        print("No evaluation questions found.")
        return

    results = []

    for index, case in enumerate(test_cases, start=1):

        question = case["question"]

        relevant_ids = normalize_ids(
            case.get("relevant_cve_ids", [])
        )

        print("\n" + "=" * 55)
        print(f"Test Case: TC-{index:02d}")
        print(f"Question: {question}")
        print("=" * 55)

        retrieved = search_threats(
            question,
            top_k=TOP_K,
        )

        ranked_ids = [
            item["cve_id"]
            for item in retrieved
            if item.get("cve_id")
        ]

        # Calculate metrics
        hit = hit_at_k(
            ranked_ids,
            relevant_ids,
            TOP_K,
        )

        precision = precision_at_k(
            ranked_ids,
            relevant_ids,
            TOP_K,
        )

        recall = recall_at_k(
            ranked_ids,
            relevant_ids,
            TOP_K,
        )

        rr = reciprocal_rank(
            ranked_ids,
            relevant_ids,
        )

        ndcg = ndcg_at_k(
            ranked_ids,
            relevant_ids,
            TOP_K,
        )

        results.append({
            "test_case": f"TC-{index:02d}",
            "question": question,
            "hit_at_5": hit,
            "precision_at_5": round(precision, 4),
            "recall_at_5": round(recall, 4),
            "reciprocal_rank": round(rr, 4),
            "ndcg_at_5": round(ndcg, 4),
            "relevant_cves": "; ".join(sorted(relevant_ids)),
            "retrieved_cves": "; ".join(ranked_ids),
        })

        print(f"Hit@{TOP_K}:       {hit}")
        print(f"Precision@{TOP_K}: {precision:.4f}")
        print(f"Recall@{TOP_K}:    {recall:.4f}")
        print(f"MRR:               {rr:.4f}")
        print(f"NDCG@{TOP_K}:      {ndcg:.4f}")

        print("\nRetrieved CVEs:")
        for rank, cve in enumerate(ranked_ids, start=1):
            marker = "RELEVANT" if cve.upper() in relevant_ids else "OTHER"
            print(f"{rank}. {cve} [{marker}]")

    # --------------------------------------------------
    # Save detailed results
    # --------------------------------------------------

    fieldnames = [
        "test_case",
        "question",
        "hit_at_5",
        "precision_at_5",
        "recall_at_5",
        "reciprocal_rank",
        "ndcg_at_5",
        "relevant_cves",
        "retrieved_cves",
    ]

    with RESULTS_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(results)

    # --------------------------------------------------
    # Aggregate metrics
    # --------------------------------------------------

    count = len(results)

    def average(metric):
        return sum(
            result[metric]
            for result in results
        ) / count

    print("\n" + "=" * 55)
    print("CYBERSTREAM RAG - RETRIEVAL EVALUATION")
    print("=" * 55)

    print(f"Test questions: {count}")
    print(f"Hit@{TOP_K}:       {average('hit_at_5'):.4f}")
    print(f"Precision@{TOP_K}: {average('precision_at_5'):.4f}")
    print(f"Recall@{TOP_K}:    {average('recall_at_5'):.4f}")
    print(f"MRR:               {average('reciprocal_rank'):.4f}")
    print(f"NDCG@{TOP_K}:      {average('ndcg_at_5'):.4f}")

    print("\nDetailed results saved to:")
    print(RESULTS_FILE)


if __name__ == "__main__":
    main()
