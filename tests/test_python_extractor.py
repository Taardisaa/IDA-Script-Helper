"""Tests for the Python call chain extractor."""

import shutil
from pathlib import Path

import pytest

from ida_api_mcp.config import Config
from ida_api_mcp.extractor.models import SourceFile, TrustLevel
from ida_api_mcp.extractor.python_call_chain import (
    extract_workflows_from_python,
)
from ida_api_mcp.parser.stub_parser import build_api_names_from_stubs


def _make_source_file(path: Path) -> SourceFile:
    return SourceFile(path=path, trust_level=TrustLevel.HIGHEST, category="test")


@pytest.fixture
def mock_python_dir(fixtures_dir, tmp_path):
    """Create a mock IDAPython directory with stubs."""
    stubs_dir = tmp_path / "3"
    stubs_dir.mkdir()
    shutil.copy(fixtures_dir / "sample_stub.py", stubs_dir / "ida_funcs.py")
    return tmp_path


@pytest.fixture
def python_api_context(mock_python_dir):
    """Build known API names and module_apis from mock stubs."""
    all_names, module_apis = build_api_names_from_stubs(mock_python_dir)
    # Add some extra names that our example script uses
    all_names.update({"get_screen_ea", "FlowChart"})
    module_apis.setdefault("ida_kernwin", set()).add("get_screen_ea")
    module_apis.setdefault("ida_gdl", set()).add("FlowChart")
    return all_names, module_apis


def test_extract_python_workflows(fixtures_dir, python_api_context):
    """Test basic workflow extraction from a Python script."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    assert len(workflows) >= 1


def test_python_workflow_api_detection(fixtures_dir, python_api_context):
    """Test that module-qualified API calls are detected."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    # Collect all API names across all workflows
    all_api_names = set()
    for w in workflows:
        all_api_names.update(w.api_names_used)

    # Module-qualified calls like ida_funcs.get_func should be detected
    assert "get_func" in all_api_names
    assert "get_func_name" in all_api_names
    assert "get_screen_ea" in all_api_names


def test_python_workflow_description_from_metadata(fixtures_dir, python_api_context):
    """Test that description is extracted from script metadata."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    # At least one workflow should use the summary metadata
    descriptions = [w.description for w in workflows]
    assert any("list all functions" in d for d in descriptions)


def test_python_workflow_data_flow(fixtures_dir, python_api_context):
    """Test that data flow edges are built from variable assignments."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    # The module-level code assigns func = get_func(ea), then uses func
    # in FlowChart(func), so there should be data flow
    module_workflows = [w for w in workflows if w.function_name == "<module>"]
    if module_workflows:
        w = module_workflows[0]
        # Check that return_var was set for get_func
        get_func_calls = [c for c in w.calls if c.method_name == "get_func"]
        if get_func_calls:
            assert get_func_calls[0].return_var == "func"


def test_python_workflow_min_calls_filter(fixtures_dir, python_api_context):
    """Test that workflows with fewer than 2 calls are filtered out."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    for w in workflows:
        assert len(w.calls) >= 2


def test_python_workflow_trust_and_category(fixtures_dir, python_api_context):
    """Test that trust level and category are propagated."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    for w in workflows:
        assert w.trust_level == TrustLevel.HIGHEST
        assert w.category == "test"


def test_python_workflow_id_is_stable(fixtures_dir, python_api_context):
    """Test that workflow IDs are deterministic."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows1 = extract_workflows_from_python(sf, known_api_names, module_apis, config)
    workflows2 = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    assert len(workflows1) == len(workflows2)
    for w1, w2 in zip(workflows1, workflows2):
        assert w1.id == w2.id


def test_python_workflow_display_text(fixtures_dir, python_api_context):
    """Test that display text is generated correctly."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    for w in workflows:
        text = w.to_display_text()
        assert "Workflow:" in text
        assert "1." in text


def test_python_workflow_embedding_text(fixtures_dir, python_api_context):
    """Test that embedding text includes API names."""
    known_api_names, module_apis = python_api_context
    sf = _make_source_file(fixtures_dir / "sample_ida_script.py")
    config = Config()

    workflows = extract_workflows_from_python(sf, known_api_names, module_apis, config)

    for w in workflows:
        text = w.to_embedding_text()
        assert "Steps:" in text
