"""Tests for the ChromaDB indexer and search."""

import tempfile
from pathlib import Path

import pytest

from ida_sdk_workflow_mcp.config import Config
from ida_sdk_workflow_mcp.extractor.call_chain import extract_workflows_from_source
from ida_sdk_workflow_mcp.extractor.models import SourceFile, TrustLevel
from ida_sdk_workflow_mcp.indexer.search import WorkflowSearcher
from ida_sdk_workflow_mcp.indexer.store import (
    build_api_docs_index,
    build_workflow_index,
    get_client,
)

KNOWN_API_NAMES = {
    "get_screen_ea", "get_func", "get_func_name", "msg",
    "get_name", "get_entry_qty", "get_entry_ordinal", "get_entry",
    "get_entry_name", "jumpto", "auto_is_ok", "ask_yn",
}


@pytest.fixture
def test_workflows(fixtures_dir):
    """Extract workflows from all test fixtures."""
    config = Config()
    all_workflows = []
    for cpp_file in fixtures_dir.glob("*.cpp"):
        sf = SourceFile(path=cpp_file, trust_level=TrustLevel.HIGHEST, category="test")
        workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)
        all_workflows.extend(workflows)
    return all_workflows


TEST_API_BRIEFS = {
    "get_func": "Get pointer to function structure by address",
    "get_screen_ea": "Get linear address of current screen cursor",
    "get_func_name": "Get function name by address",
    "msg": "Output a formatted string to the message window",
    "get_entry_qty": "Get number of entry points",
    "get_entry_ordinal": "Get entry point ordinal number",
    "get_entry": "Get entry point address by its ordinal",
    "get_entry_name": "Get name of entry point by ordinal",
}


@pytest.fixture
def indexed_db(test_workflows):
    """Create a temporary ChromaDB with indexed test workflows."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_chroma"
        client = get_client(db_path)
        build_workflow_index(client, test_workflows, api_briefs=TEST_API_BRIEFS)
        build_api_docs_index(client, test_workflows)
        yield db_path


def test_build_index_succeeds(test_workflows):
    """Index building should not raise errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_chroma"
        client = get_client(db_path)
        build_workflow_index(client, test_workflows)
        build_api_docs_index(client, test_workflows)


def test_search_workflows_func(indexed_db):
    searcher = WorkflowSearcher(indexed_db)
    results = searcher.search_workflows("get function at an address")

    assert len(results) > 0
    top = results[0]
    assert "get_func" in top.get("apis_used", "")


def test_search_workflows_xref(indexed_db):
    searcher = WorkflowSearcher(indexed_db)
    results = searcher.search_workflows("cross references to an address")

    assert len(results) > 0


def test_get_api_doc_exact(indexed_db):
    searcher = WorkflowSearcher(indexed_db)
    results = searcher.get_api_doc("get_func")

    assert len(results) > 0
    assert any(r.get("name") == "get_func" for r in results)


def test_get_api_doc_fuzzy(indexed_db):
    searcher = WorkflowSearcher(indexed_db)
    results = searcher.get_api_doc("function")

    assert len(results) > 0


def test_list_related_apis(indexed_db):
    searcher = WorkflowSearcher(indexed_db)
    result = searcher.list_related_apis("get_func")

    assert result["queried"] == "get_func"
    assert result["workflow_count"] > 0
    related_names = {r["api"] for r in result["related"]}
    # get_func_name or msg should co-occur with get_func
    assert len(related_names) > 0


def test_empty_index():
    """Searching an empty index should not crash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "empty_chroma"
        client = get_client(db_path)
        build_workflow_index(client, [])
        build_api_docs_index(client, [])

        searcher = WorkflowSearcher(db_path)
        results = searcher.search_workflows("anything")
        assert results == []
