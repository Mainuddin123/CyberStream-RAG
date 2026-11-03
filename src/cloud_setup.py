
import sqlite3

import chromadb
import streamlit as st

from src.collector import fetch_threats
from src.indexer import index_threats
from src.storage import save_threats, DB_PATH
from src.search import CHROMA_DIR, COLLECTION_NAME


def sqlite_has_records():
    """Check whether the SQLite database contains threats."""

    if not DB_PATH.exists():
        return False

    try:
        with sqlite3.connect(DB_PATH) as connection:
            result = connection.execute(
                "SELECT COUNT(*) FROM threats"
            ).fetchone()

        return result is not None and result[0] > 0

    except sqlite3.Error:
        return False


@st.cache_resource(show_spinner=False)
def initialize_cloud_knowledge_base():
    """Initialize SQLite and ChromaDB independently."""

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR)
    )

    try:
        collection = client.get_collection(
            name=COLLECTION_NAME
        )
        chroma_ready = collection.count() > 0

    except Exception:
        collection = None
        chroma_ready = False

    sqlite_ready = sqlite_has_records()

    # Fetch CISA data if either database needs initialization.
    if not sqlite_ready or not chroma_ready:

        with st.spinner(
            "Downloading CISA threat intelligence..."
        ):
            threats = fetch_threats()

        if not threats:
            raise RuntimeError(
                "CISA returned no vulnerability records."
            )

        # Initialize SQLite for catalog analytics.
        if not sqlite_ready:
            with st.spinner(
                "Saving CISA records to SQLite..."
            ):
                save_threats(threats)

        # Initialize ChromaDB for RAG retrieval.
        if not chroma_ready:
            with st.spinner(
                "Building ChromaDB vector index..."
            ):
                index_threats()

    collection = client.get_collection(
        name=COLLECTION_NAME
    )

    if collection.count() == 0:
        raise RuntimeError(
            "ChromaDB initialization failed."
        )

    if not sqlite_has_records():
        raise RuntimeError(
            "SQLite initialization failed."
        )

    with sqlite3.connect(DB_PATH) as connection:
        sqlite_count = connection.execute(
            "SELECT COUNT(*) FROM threats"
        ).fetchone()[0]

    return {
        "status": "ready",
        "records": sqlite_count,
        "chroma_records": collection.count(),
        "message": "CISA knowledge base initialized."
    }
