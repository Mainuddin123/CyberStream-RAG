
import json
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "data" / "threats.json"
CHROMA_DIR = PROJECT_ROOT / "data" / "chroma"

COLLECTION_NAME = "cyber_threats"
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def index_threats():
    threats = json.loads(DATA_FILE.read_text(encoding="utf-8"))

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    model = SentenceTransformer(MODEL_NAME)

    ids = []
    documents = []
    metadatas = []

    for threat in threats:
        cve_id = threat.get("cveID")
        if not cve_id:
            continue

        name = threat.get("vulnerabilityName", "")
        description = threat.get("shortDescription", "")
        vendor = threat.get("vendorProject", "")
        product = threat.get("product", "")

        text = (
            f"CVE: {cve_id}. "
            f"Vulnerability: {name}. "
            f"Description: {description}. "
            f"Vendor: {vendor}. Product: {product}."
        )

        ids.append(cve_id)
        documents.append(text)
        metadatas.append({
            "cve_id": cve_id,
            "name": name,
            "vendor": vendor,
            "product": product,
            "date_added": threat.get("dateAdded", ""),
        })

    batch_size = 100

    for start in range(0, len(ids), batch_size):
        end = start + batch_size

        batch_documents = documents[start:end]
        embeddings = model.encode(
            batch_documents,
            normalize_embeddings=True,
            show_progress_bar=False,
        ).tolist()

        collection.upsert(
            ids=ids[start:end],
            documents=batch_documents,
            metadatas=metadatas[start:end],
            embeddings=embeddings,
        )

        print(f"Indexed {min(end, len(ids))}/{len(ids)} threats")

    print("Total indexed:", collection.count())
    print("ChromaDB path:", CHROMA_DIR)


if __name__ == "__main__":
    index_threats()
