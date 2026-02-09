"""Tests for the header comment parser (html_parser.py)."""

from pathlib import Path

from ida_sdk_workflow_mcp.parser.html_parser import parse_header_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_header_finds_functions():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    func_names = {d.name for d in docs if d.kind == "function"}

    assert "enable_flags" in func_names
    assert "next_addr" in func_names
    assert "get_func" in func_names
    assert "del_func" in func_names


def test_parse_header_function_brief():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    by_name = {d.name: d for d in docs}

    assert "Allocate flags for address range" in by_name["enable_flags"].brief
    assert "Get next address" in by_name["next_addr"].brief


def test_parse_header_function_params():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    by_name = {d.name: d for d in docs}

    enable = by_name["enable_flags"]
    param_names = [p[0] for p in enable.params]
    assert "start_ea" in param_names
    assert "end_ea" in param_names
    assert "stt" in param_names


def test_parse_header_function_return():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    by_name = {d.name: d for d in docs}

    assert by_name["enable_flags"].return_desc != ""
    assert "0 if ok" in by_name["enable_flags"].return_desc


def test_parse_header_function_signature():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    by_name = {d.name: d for d in docs}

    assert "ea_t start_ea" in by_name["enable_flags"].signature
    assert "func_t" in by_name["get_func"].signature


def test_parse_header_finds_class():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    classes = [d for d in docs if d.kind == "class"]

    assert len(classes) >= 1
    assert any(d.name == "func_t" for d in classes)


def test_parse_header_class_brief():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    by_name = {d.name: d for d in docs}

    assert "function" in by_name["func_t"].brief.lower()


def test_parse_header_file_name():
    docs = parse_header_file(FIXTURES_DIR / "sample_header.hpp")
    for d in docs:
        assert d.header_file == "sample_header.hpp"


def test_parse_nonexistent_file():
    docs = parse_header_file(Path("/nonexistent/file.hpp"))
    assert docs == []
