
from pathlib import Path
import os
import re

import chromadb
from dotenv import load_dotenv
from google import genai
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer
from flashrank import Ranker, RerankRequest

from langsmith import traceable
from langsmith.run_helpers import tracing_context

# --------------------------------------------------
# Configuration
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHROMA_DIR = PROJECT_ROOT / "data" / "chroma"

COLLECTION_NAME = "cyber_threats"
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
GENERATION_MODEL_NAME = "gemini-3.5-flash"

RRF_K = 60
CANDIDATE_K = 20
MAX_QUERY_VARIANTS = 3

load_dotenv(PROJECT_ROOT / ".env")

# Load models once when the module starts
print("Loading embedding model...")
embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)

print("Loading FlashRank reranker...")
reranker = Ranker(model_name="ms-marco-MiniLM-L-12-v2")


# --------------------------------------------------
# Text processing
# --------------------------------------------------

def tokenize(text):
    """Tokenize words, product names, and CVE identifiers."""
    return re.findall(
        r"[a-z0-9]+(?:[-._][a-z0-9]+)*",
        text.lower(),
    )


def build_search_text(document, metadata):
    """Combine document text and metadata for BM25."""
    metadata = metadata or {}

    fields = [
        metadata.get("cve_id", ""),
        metadata.get("name", ""),
        metadata.get("vendor", ""),
        metadata.get("product", ""),
        metadata.get("date_added", ""),
        document or "",
    ]

    return " ".join(str(field) for field in fields)


# --------------------------------------------------
# Multi-Query Retrieval
# --------------------------------------------------

@traceable(name="Generate Query Variants", run_type="llm")
def generate_query_variants(query):
    """
    Generate alternative queries using Gemini.
    Fall back to the original query if Gemini fails.
    """
    original_query = query.strip()
    queries = [original_query]

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        print("Gemini API key unavailable; using original query.")
        return queries

    prompt = f"""
Generate up to {MAX_QUERY_VARIANTS} alternative search queries
for a cybersecurity threat intelligence database.

Rules:
- Preserve exact CVE IDs, vendors, and product names.
- Use different relevant wording where useful.
- Return only one query per line.
- Do not number the queries or add explanations.

Original question:
{original_query}
"""

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model=GENERATION_MODEL_NAME,
            contents=prompt,
        )

        if response.text:
            for line in response.text.splitlines():
                alternative = re.sub(
                    r"^\s*(?:[-*•]|\d+[.)])\s*",
                    "",
                    line,
                ).strip().strip('"')

                if (
                    alternative
                    and alternative.lower() not in {
                        item.lower() for item in queries
                    }
                ):
                    queries.append(alternative)

                if len(queries) >= MAX_QUERY_VARIANTS + 1:
                    break

    except Exception as error:
        print(
            "Query rewriting unavailable; "
            f"using available queries. Reason: {error}"
        )

    print(f"Search query variants: {len(queries)}")
    for item in queries:
        print(f"  - {item}")

    return queries


# --------------------------------------------------
# Reciprocal Rank Fusion
# --------------------------------------------------

def reciprocal_rank_fusion(rankings, k=RRF_K):
    """Combine ranked lists and deduplicate by record ID."""
    scores = {}
    records = {}

    for ranking in rankings:
        seen_in_ranking = set()

        for rank, record in enumerate(ranking, start=1):
            record_id = record["id"]

            # Avoid counting a duplicate more than once
            # within the same ranking.
            if record_id in seen_in_ranking:
                continue

            seen_in_ranking.add(record_id)

            scores[record_id] = (
                scores.get(record_id, 0.0)
                + 1.0 / (k + rank)
            )

            records[record_id] = record

    ranked_ids = sorted(
        scores,
        key=lambda record_id: scores[record_id],
        reverse=True,
    )

    results = []

    for record_id in ranked_ids:
        item = records[record_id].copy()
        item["rrf_score"] = scores[record_id]
        results.append(item)

    return results


# --------------------------------------------------
# Hybrid Search + Multi-Query + FlashRank
# --------------------------------------------------

@traceable(name="CyberStream Hybrid Retrieval", run_type="chain")
def search_threats(query, top_k=5):
    """
    Retrieval pipeline:
    1. Multi-query generation
    2. ChromaDB semantic search
    3. BM25 keyword search
    4. Reciprocal Rank Fusion
    5. FlashRank reranking
    """
    if not query or not query.strip():
        return []

    if top_k < 1:
        return []

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR)
    )

    collection = client.get_collection(
        name=COLLECTION_NAME
    )

    total_records = collection.count()

    if total_records == 0:
        return []

    # Retrieve records for keyword search.
    stored = collection.get(
        include=["documents", "metadatas"]
    )

    documents = stored.get("documents") or []
    metadatas = stored.get("metadatas") or []
    ids = stored.get("ids") or []

    corpus = []
    records_by_id = {}

    for record_id, document, metadata in zip(
        ids, documents, metadatas
    ):
        metadata = metadata or {}

        corpus.append(
            tokenize(build_search_text(document, metadata))
        )

        records_by_id[record_id] = {
            "id": record_id,
            "cve_id": metadata.get("cve_id", "Unknown"),
            "name": metadata.get("name", "Unknown"),
            "vendor": metadata.get("vendor", "Unknown"),
            "product": metadata.get("product", "Unknown"),
            "date_added": metadata.get("date_added", ""),
            "details": document or "",
        }

    # 1. Generate alternative queries.
    query_variants = generate_query_variants(query)

    # 2. Semantic vector search for each query.
    vector_candidates = {}

    for search_query in query_variants:
        embedding = embedding_model.encode(
            search_query,
            normalize_embeddings=True,
        ).tolist()

        vector_results = collection.query(
            query_embeddings=[embedding],
            n_results=min(CANDIDATE_K, total_records),
            include=["documents", "metadatas", "distances"],
        )

        result_ids = vector_results.get("ids", [[]])[0]
        distances = vector_results.get("distances", [[]])[0]

        for record_id, distance in zip(result_ids, distances):
            if record_id not in records_by_id:
                continue

            item = records_by_id[record_id].copy()
            item["distance"] = float(distance)

            # Keep the best (lowest) distance for this record.
            previous = vector_candidates.get(record_id)

            if (
                previous is None
                or item["distance"] < previous["distance"]
            ):
                vector_candidates[record_id] = item

    vector_ranking = sorted(
        vector_candidates.values(),
        key=lambda item: item["distance"],
    )

    # 3. BM25 keyword search across all query variants.
    keyword_candidates = {}

    tokenized_queries = [
        tokenize(search_query)
        for search_query in query_variants
    ]

    tokenized_queries = [
        tokens for tokens in tokenized_queries if tokens
    ]

    if tokenized_queries and corpus:
        bm25 = BM25Okapi(corpus)

        for tokens in tokenized_queries:
            scores = bm25.get_scores(tokens)

            for index, score in enumerate(scores):
                if score <= 0:
                    continue

                record_id = ids[index]

                keyword_candidates[record_id] = (
                    keyword_candidates.get(record_id, 0.0)
                    + float(score)
                )

    ranked_keyword_ids = sorted(
        keyword_candidates,
        key=lambda record_id: keyword_candidates[record_id],
        reverse=True,
    )[:CANDIDATE_K]

    keyword_ranking = []

    for record_id in ranked_keyword_ids:
        item = records_by_id[record_id].copy()
        item["bm25_score"] = keyword_candidates[record_id]
        keyword_ranking.append(item)

    # 4. Combine vector and keyword rankings.
    fused_results = reciprocal_rank_fusion(
        [vector_ranking, keyword_ranking]
    )

    if not fused_results:
        return []

    # Rerank a bounded candidate set for efficiency.
    candidates = fused_results[:CANDIDATE_K]

    passages = []

    for item in candidates:
        text = (
            f"CVE: {item['cve_id']}. "
            f"Name: {item['name']}. "
            f"Vendor: {item['vendor']}. "
            f"Product: {item['product']}. "
            f"Date added: {item['date_added']}. "
            f"Details: {item['details']}"
        )

        passages.append({
            "id": item["id"],
            "text": text,
            "meta": item,
        })

    request = RerankRequest(
        query=query,
        passages=passages,
    )

    reranked_results = reranker.rerank(request)

    final_results = []

    for result in reranked_results[:top_k]:
        item = result["meta"].copy()
        item["rerank_score"] = float(result["score"])
        final_results.append(item)

    return final_results


# --------------------------------------------------
# Command-line test
# --------------------------------------------------

if __name__ == "__main__":
    print("\nCyberStream RAG - Advanced Hybrid Search")
    print("Multi-Query + BM25 + Vector Search + RRF + FlashRank")
    print("Type 'exit' to quit.")

    while True:
        question = input(
            "\nAsk about cybersecurity threats: "
        ).strip()

        if question.lower() in {"exit", "quit"}:
            break

        if not question:
            print("Please enter a question.")
            continue

        try:
            matches = search_threats(question)

            if not matches:
                print("No matching records found.")
                continue

            for index, item in enumerate(matches, start=1):
                print(f"\n--- Result {index} ---")
                print(f"CVE: {item['cve_id']}")
                print(f"Name: {item['name']}")
                print(f"Vendor: {item['vendor']}")
                print(f"Product: {item['product']}")
                print(f"Date added: {item['date_added']}")
                print(f"RRF score: {item['rrf_score']:.6f}")
                print(
                    f"Rerank score: {item['rerank_score']:.4f}"
                )

                if "distance" in item:
                    print(
                        f"Vector distance: {item['distance']:.4f}"
                    )

                if "bm25_score" in item:
                    print(
                        f"BM25 score: {item['bm25_score']:.4f}"
                    )

                print(f"Details: {item['details']}")

        except Exception as error:
            print(f"Search error: {error}")
