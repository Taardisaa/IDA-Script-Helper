"""Tests for MCP server tool functions."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ida_api_mcp.config import Config
from ida_api_mcp.extractor.call_chain import extract_workflows_from_source
from ida_api_mcp.extractor.models import SourceFile, TrustLevel
from ida_api_mcp.indexer.search import WorkflowSearcher
from ida_api_mcp.indexer.store import (
    build_api_docs_index,
    build_workflow_index,
    get_client,
)
from ida_api_mcp.server import (
    clear_index,
    get_api_doc,
    get_index_info,
    get_versions,
    get_workflows,
    initialize_index,
    list_related_apis,
    select_version,
)

KNOWN_API_NAMES = {
    "get_screen_ea",
    "get_func",
    "get_func_name",
    "msg",
    "get_name",
    "get_entry_qty",
    "get_entry_ordinal",
    "get_entry",
    "get_entry_name",
    "jumpto",
    "auto_is_ok",
    "ask_yn",
}

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def server_with_index():
    """Set up a test index and patch the server's searcher."""
    config = Config()
    all_workflows = []
    for cpp_file in FIXTURES_DIR.glob("*.cpp"):
        sf = SourceFile(path=cpp_file, trust_level=TrustLevel.HIGHEST, category="test")
        workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)
        all_workflows.extend(workflows)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "v84"
        db_path.mkdir()
        client = get_client(db_path)
        build_workflow_index(client, all_workflows)
        build_api_docs_index(client, all_workflows)

        searcher = WorkflowSearcher(db_path)
        with (
            patch("ida_api_mcp.server._searcher", searcher),
            patch("ida_api_mcp.server._active_version", "84"),
            patch(
                "ida_api_mcp.server._config", Config(db_base_path=Path(tmpdir))
            ),
        ):
            yield


def test_get_workflows_returns_results(server_with_index):
    result = get_workflows("get the function at an address")
    assert "Result 1" in result
    assert "get_func" in result


def test_get_workflows_no_match(server_with_index):
    result = get_workflows("zzzzz_nonexistent_zzzzz")
    assert isinstance(result, str)


def test_get_api_doc_returns_results(server_with_index):
    result = get_api_doc("get_func")
    assert "get_func" in result


def test_list_related_apis_returns_results(server_with_index):
    result = list_related_apis("get_func")
    assert "get_func" in result


def test_get_versions(server_with_index):
    result = get_versions()
    assert "v84" in result


def test_select_version_valid(server_with_index):
    result = select_version("84")
    assert "v84" in result


def test_select_version_invalid(server_with_index):
    result = select_version("999")
    assert "not indexed" in result


def test_get_index_info(server_with_index):
    result = get_index_info()
    assert "SDK version" in result
    assert "Workflows" in result


def test_clear_index(server_with_index):
    result = clear_index("84")
    assert "cleared" in result.lower()


def test_initialize_index_failure_message():
    result = initialize_index("/does/not/exist", "84")
    assert "Failed to build index" in result
