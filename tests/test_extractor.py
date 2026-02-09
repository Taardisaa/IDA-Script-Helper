"""Tests for the call chain extractor."""

from pathlib import Path

from ida_sdk_workflow_mcp.config import Config
from ida_sdk_workflow_mcp.extractor.call_chain import extract_workflows_from_source
from ida_sdk_workflow_mcp.extractor.models import SourceFile, TrustLevel


def _make_source_file(path: Path, trust: TrustLevel = TrustLevel.HIGHEST) -> SourceFile:
    return SourceFile(path=path, trust_level=trust, category="test")


# A minimal set of known IDA API names for testing
KNOWN_API_NAMES = {
    "get_screen_ea", "get_func", "get_func_name", "msg",
    "get_name", "get_entry_qty", "get_entry_ordinal", "get_entry",
    "get_entry_name", "jumpto", "auto_is_ok", "ask_yn",
}


def test_extract_decompile_workflow(fixtures_dir):
    sf = _make_source_file(fixtures_dir / "decompile_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    assert len(workflows) >= 1
    # Find the run method workflow
    run_workflows = [w for w in workflows if "run" in w.function_name]
    assert len(run_workflows) >= 1
    w = run_workflows[0]

    assert w.trust_level == TrustLevel.HIGHEST

    # Should have multiple API calls
    assert len(w.calls) >= 2

    # Check that key APIs are detected
    method_names = {c.method_name for c in w.calls}
    assert "get_screen_ea" in method_names
    assert "get_func" in method_names


def test_extract_decompile_data_flow(fixtures_dir):
    sf = _make_source_file(fixtures_dir / "decompile_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    run_workflows = [w for w in workflows if "run" in w.function_name]
    assert len(run_workflows) >= 1
    w = run_workflows[0]

    # There should be data flow edges
    assert len(w.data_flow) > 0


def test_extract_xref_workflows(fixtures_dir):
    sf = _make_source_file(fixtures_dir / "xref_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    # Should extract workflows from both functions
    assert len(workflows) == 2
    names = {w.function_name for w in workflows}
    assert "show_xrefs_to" in names
    assert "show_xrefs_from" in names


def test_extract_entry_lister(fixtures_dir):
    sf = _make_source_file(fixtures_dir / "simple_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    assert len(workflows) >= 1
    run_workflows = [w for w in workflows if "run" in w.function_name]
    assert len(run_workflows) >= 1
    w = run_workflows[0]

    method_names = {c.method_name for c in w.calls}
    assert "get_entry_qty" in method_names
    assert "get_entry_ordinal" in method_names


def test_workflow_display_text(fixtures_dir):
    sf = _make_source_file(fixtures_dir / "decompile_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    w = [w for w in workflows if "run" in w.function_name][0]
    text = w.to_display_text()

    assert "Workflow:" in text
    assert "1." in text  # First step numbered


def test_workflow_embedding_text(fixtures_dir):
    sf = _make_source_file(fixtures_dir / "decompile_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    w = [w for w in workflows if "run" in w.function_name][0]
    text = w.to_embedding_text()

    assert "get_func" in text
    assert "Steps:" in text


def test_workflow_embedding_text_with_briefs(fixtures_dir):
    """to_embedding_text() should include API briefs when available."""
    sf = _make_source_file(fixtures_dir / "decompile_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    w = [w for w in workflows if "run" in w.function_name][0]
    w.api_briefs = {
        "get_func": "Get pointer to function structure by address",
        "get_screen_ea": "Get linear address of current screen cursor",
    }
    text = w.to_embedding_text()

    assert "Get pointer to function structure by address" in text
    assert "get_func" in text
    assert "Steps:" in text


def test_workflow_id_is_stable(fixtures_dir):
    sf = _make_source_file(fixtures_dir / "decompile_plugin.cpp")
    config = Config()

    workflows1 = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)
    workflows2 = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    assert workflows1[0].id == workflows2[0].id


def test_min_calls_filter(fixtures_dir):
    """Workflows with fewer than 2 calls should be filtered out."""
    sf = _make_source_file(fixtures_dir / "decompile_plugin.cpp")
    config = Config()
    workflows = extract_workflows_from_source(sf, KNOWN_API_NAMES, config)

    for w in workflows:
        assert len(w.calls) >= 2
