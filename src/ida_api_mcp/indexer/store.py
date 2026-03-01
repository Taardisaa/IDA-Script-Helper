"""ChromaDB ingestion and persistence for extracted workflows and API docs."""

from __future__ import annotations

import datetime
import logging
from pathlib import Path

import chromadb

from ida_api_mcp.extractor.models import HeaderApiDoc, Workflow

logger = logging.getLogger(__name__)

WORKFLOWS_COLLECTION = "workflows"
API_DOCS_COLLECTION = "api_docs"


def get_client(db_path: Path) -> chromadb.ClientAPI:
    """Get a persistent ChromaDB client."""
    db_path.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(db_path))


def clear_index(client: chromadb.ClientAPI) -> None:
    """Drop both ChromaDB collections, leaving an empty database."""
    for name in (WORKFLOWS_COLLECTION, API_DOCS_COLLECTION):
        try:
            client.delete_collection(name)
        except Exception:
            pass


def get_index_info(client: chromadb.ClientAPI) -> dict:
    """Return metadata about the current index (version, build time, counts)."""
    info: dict = {
        "sdk_version": "unknown",
        "indexed_at": "unknown",
        "workflow_count": 0,
        "api_doc_count": 0,
    }

    try:
        workflows = client.get_collection(WORKFLOWS_COLLECTION)
        meta = workflows.metadata or {}
        info["sdk_version"] = meta.get("sdk_version", "unknown")
        info["indexed_at"] = meta.get("indexed_at", "unknown")
        info["workflow_count"] = workflows.count()
    except Exception:
        pass

    try:
        info["api_doc_count"] = client.get_collection(API_DOCS_COLLECTION).count()
    except Exception:
        pass

    return info


def build_workflow_index(
    client: chromadb.ClientAPI,
    workflows: list[Workflow],
    api_briefs: dict[str, str] | None = None,
    sdk_version: str = "unknown",
    indexed_at: str = "",
) -> None:
    """Ingest extracted workflows into ChromaDB.

    Args:
        client: ChromaDB client.
        workflows: List of extracted workflows.
        api_briefs: Optional mapping of API name -> brief description
            from header docs, injected into each workflow before embedding.
    """
    # Inject API briefs into workflows so to_embedding_text() can use them
    if api_briefs:
        for w in workflows:
            w.api_briefs = api_briefs

    if not indexed_at:
        indexed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        client.delete_collection(WORKFLOWS_COLLECTION)
    except Exception:
        pass

    collection = client.create_collection(
        name=WORKFLOWS_COLLECTION,
        metadata={
            "hnsw:space": "cosine",
            "sdk_version": sdk_version,
            "indexed_at": indexed_at,
        },
    )

    if not workflows:
        logger.warning("No workflows to index")
        return

    batch_size = 500
    for i in range(0, len(workflows), batch_size):
        batch = workflows[i : i + batch_size]
        collection.add(
            ids=[w.id for w in batch],
            documents=[w.to_embedding_text() for w in batch],
            metadatas=[_workflow_to_metadata(w) for w in batch],
        )

    logger.info("Indexed %d workflows into ChromaDB", len(workflows))


def build_api_docs_index(
    client: chromadb.ClientAPI,
    workflows: list[Workflow],
    api_docs: list[HeaderApiDoc] | None = None,
) -> None:
    """Build the API docs index from workflows and header docs.

    Merges Doxygen header docs with workflow usage counts to produce
    a searchable collection for get_api_doc lookups.
    """
    try:
        client.delete_collection(API_DOCS_COLLECTION)
    except Exception:
        pass

    collection = client.create_collection(
        name=API_DOCS_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )

    # Aggregate API info from workflows
    api_info: dict[str, dict] = {}
    for w in workflows:
        for call in w.calls:
            name = call.method_name
            if name not in api_info:
                api_info[name] = {
                    "name": name,
                    "class_name": call.class_name,
                    "workflow_count": 0,
                    "example_file": w.file_path,
                    "brief": "",
                    "signature": "",
                    "header_file": "",
                    "co_apis": set(),
                }
            api_info[name]["workflow_count"] += 1
            # Track co-occurring APIs
            for other in w.calls:
                if other.method_name != name:
                    api_info[name]["co_apis"].add(other.method_name)

    # Merge header docs if available
    if api_docs:
        for doc in api_docs:
            if doc.kind != "function":
                # Also index structs/classes
                key = doc.name
                if key not in api_info:
                    api_info[key] = {
                        "name": key,
                        "class_name": "",
                        "workflow_count": 0,
                        "example_file": "",
                        "brief": doc.brief,
                        "signature": doc.signature,
                        "header_file": doc.header_file,
                        "co_apis": set(),
                    }
                else:
                    api_info[key]["brief"] = doc.brief
                    api_info[key]["signature"] = doc.signature
                    api_info[key]["header_file"] = doc.header_file
                continue

            name = doc.name
            if name in api_info:
                api_info[name]["brief"] = doc.brief
                api_info[name]["signature"] = doc.signature
                api_info[name]["header_file"] = doc.header_file
            else:
                api_info[name] = {
                    "name": name,
                    "class_name": "",
                    "workflow_count": 0,
                    "example_file": "",
                    "brief": doc.brief,
                    "signature": doc.signature,
                    "header_file": doc.header_file,
                    "co_apis": set(),
                }

    if not api_info:
        logger.warning("No API docs to index")
        return

    ids = []
    documents = []
    metadatas = []
    for name, info in api_info.items():
        brief = info.get("brief", "")
        sig = info.get("signature", "")
        doc_text = f"IDA SDK API {name}. {brief} Signature: {sig}"
        ids.append(name)
        documents.append(doc_text)
        metadatas.append(
            {
                "name": name,
                "class_name": info.get("class_name", ""),
                "brief": brief[:500],
                "signature": sig[:1000],
                "header_file": info.get("header_file", ""),
                "workflow_count": info["workflow_count"],
                "example_file": info.get("example_file", ""),
                "co_apis": ",".join(sorted(info.get("co_apis", set())))[:2000],
            }
        )

    batch_size = 500
    for i in range(0, len(ids), batch_size):
        collection.add(
            ids=ids[i : i + batch_size],
            documents=documents[i : i + batch_size],
            metadatas=metadatas[i : i + batch_size],
        )

    logger.info("Indexed %d API doc entries into ChromaDB", len(api_info))


def _infer_language(file_path: str) -> str:
    """Infer language from file extension."""
    if file_path.endswith(".py"):
        return "python"
    return "cpp"


def _workflow_to_metadata(w: Workflow) -> dict:
    """Convert a Workflow to ChromaDB metadata dict."""
    return {
        "function_name": w.function_name,
        "file_path": w.file_path,
        "trust_level": w.trust_level.value,
        "category": w.category,
        "language": _infer_language(w.file_path),
        "num_calls": len(w.calls),
        "apis_used": ",".join(sorted(w.api_names_used)),
        "description": w.description[:500],
        "source_snippet": w.source_snippet[:2000],
        "display_text": w.to_display_text()[:4000],
    }
