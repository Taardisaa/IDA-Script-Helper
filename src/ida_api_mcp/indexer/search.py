"""Search interface over the ChromaDB workflow and API docs indices."""

from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

import chromadb

from ida_api_mcp.indexer.store import (
    API_DOCS_COLLECTION,
    WORKFLOWS_COLLECTION,
    get_client,
)

logger = logging.getLogger(__name__)

# Trust level ordering for re-ranking results
_TRUST_ORDER = {"highest": 0, "high": 1, "medium": 2}


class WorkflowSearcher:
    """Stateful searcher backed by a ChromaDB persistent store."""

    def __init__(self, db_path: Path):
        self._client = get_client(db_path)
        self._workflows = self._client.get_or_create_collection(WORKFLOWS_COLLECTION)
        self._api_docs = self._client.get_or_create_collection(API_DOCS_COLLECTION)

    def search_workflows(self, query: str, n_results: int = 5) -> list[dict]:
        """Semantic search for workflows matching a task description.

        Returns ranked results with trust-level re-ranking:
        highest-trust results first, then by similarity within each tier.
        """
        if self._workflows.count() == 0:
            return []

        results = self._workflows.query(
            query_texts=[query],
            n_results=min(n_results * 3, 20),
        )

        if not results["metadatas"] or not results["metadatas"][0]:
            return []

        paired = list(zip(
            results["distances"][0],
            results["metadatas"][0],
        ))

        # Sort: trust level first, then distance
        paired.sort(key=lambda x: (
            _TRUST_ORDER.get(x[1].get("trust_level", "medium"), 2),
            x[0],
        ))

        return [meta for _, meta in paired[:n_results]]

    def get_api_doc(self, name: str, n_results: int = 5) -> list[dict]:
        """Fuzzy API name lookup.

        Tries exact match first, then falls back to semantic search.
        """
        # Try exact ID match
        try:
            exact = self._api_docs.get(ids=[name])
            if exact["metadatas"]:
                return exact["metadatas"]
        except Exception:
            pass

        # Fall back to semantic search
        if self._api_docs.count() == 0:
            return []

        results = self._api_docs.query(
            query_texts=[name],
            n_results=n_results,
        )

        if not results["metadatas"] or not results["metadatas"][0]:
            return []

        return results["metadatas"][0]

    def list_related_apis(self, name: str) -> dict:
        """Find APIs commonly co-occurring with the given API name.

        Uses both the co_apis metadata from api_docs and
        workflow-level co-occurrence analysis.
        """
        # First check the api_docs collection for direct co_apis metadata
        try:
            exact = self._api_docs.get(ids=[name])
            if exact["metadatas"] and exact["metadatas"][0].get("co_apis"):
                co_apis_str = exact["metadatas"][0]["co_apis"]
                related = []
                for api in co_apis_str.split(","):
                    api = api.strip()
                    if api:
                        related.append({"api": api, "co_occurrence_count": 1})
                if related:
                    return {
                        "queried": name,
                        "related": related[:20],
                        "workflow_count": exact["metadatas"][0].get("workflow_count", 0),
                    }
        except Exception:
            pass

        # Fall back to workflow-level analysis
        if self._workflows.count() == 0:
            return {"queried": name, "related": [], "workflow_count": 0}

        results = self._workflows.query(
            query_texts=[name],
            n_results=min(self._workflows.count(), 50),
        )

        if not results["metadatas"] or not results["metadatas"][0]:
            return {"queried": name, "related": [], "workflow_count": 0}

        # Filter to workflows that actually use this API
        matching_metas = [
            meta for meta in results["metadatas"][0]
            if name in meta.get("apis_used", "").split(",")
        ]

        if not matching_metas:
            return {"queried": name, "related": [], "workflow_count": 0}

        co_occurrence: Counter[str] = Counter()
        for meta in matching_metas:
            apis = set(meta.get("apis_used", "").split(","))
            apis.discard(name)
            apis.discard("")
            co_occurrence.update(apis)

        return {
            "queried": name,
            "related": [
                {"api": api_name, "co_occurrence_count": count}
                for api_name, count in co_occurrence.most_common(20)
            ],
            "workflow_count": len(matching_metas),
        }
