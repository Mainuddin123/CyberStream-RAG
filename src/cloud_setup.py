
import streamlit as st
import chromadb

from src.collector import fetch_threats
from src.indexer import index_threats

from src.search import CHROMA_DIR, COLLECTION_NAME


@st.cache_resource(show_spinner=False)
def initialize_cloud_knowledge_base():
    """
    Initialize the CISA knowledge base once per app instance.

    Reuse an existing ChromaDB collection when available.
    Otherwise, fetch CISA data and build the index.
    """

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR)
    )

    try:
        collection = client.get_collection(
            name=COLLECTION_NAME
        )

        if collection.count() > 0:
            return {
                "status": "ready",
                "records": collection.count(),
                "message": "Existing ChromaDB index loaded."
            }

    except Exception:
        pass

    with st.spinner(
        "Downloading CISA threat intelligence..."
    ):
        threats = fetch_threats()

    if not threats:
        raise RuntimeError(
            "CISA returned no vulnerability records."
        )

    with st.spinner(
        "Building ChromaDB vector index. First startup may take several minutes..."
    ):
        index_threats()

    collection = client.get_collection(
        name=COLLECTION_NAME
    )

    count = collection.count()

    if count == 0:
        raise RuntimeError(
            "ChromaDB initialization failed."
        )

    return {
        "status": "ready",
        "records": count,
        "message": "CISA knowledge base initialized successfully."
    }
