"""Tests for the tree-sitter C++ parser module."""

from ida_sdk_workflow_mcp.parser.cpp_parser import (
    find_base_classes,
    find_function_bodies,
    find_includes,
    parse_cpp,
)


def test_parse_cpp_returns_tree(decompile_source):
    tree = parse_cpp(decompile_source)
    assert tree is not None
    assert tree.root_node.type == "translation_unit"


def test_parse_cpp_error_recovery(decompile_source):
    """tree-sitter may report errors on IDA-specific types (ea_t, idaapi)
    but still extracts valid AST nodes through error recovery."""
    tree = parse_cpp(decompile_source)
    # Even with unknown types, we can still find functions and includes
    bodies = find_function_bodies(tree, decompile_source)
    assert len(bodies) >= 1


def test_find_includes(decompile_source):
    tree = parse_cpp(decompile_source)
    includes = find_includes(tree, decompile_source)

    assert "ida.hpp" in includes
    assert "funcs.hpp" in includes
    assert "kernwin.hpp" in includes
    assert "bytes.hpp" in includes
    assert "name.hpp" in includes


def test_find_function_bodies(decompile_source):
    tree = parse_cpp(decompile_source)
    methods = find_function_bodies(tree, decompile_source)

    names = {name for name, _ in methods}
    # Should find plugin_ctx_t::run and init
    assert "plugin_ctx_t::run" in names
    assert "init" in names


def test_find_base_classes(decompile_source):
    tree = parse_cpp(decompile_source)
    bases = find_base_classes(tree, decompile_source)

    assert "plugin_ctx_t" in bases
    assert "plugmod_t" in bases["plugin_ctx_t"]


def test_find_includes_xref(xref_source):
    tree = parse_cpp(xref_source)
    includes = find_includes(tree, xref_source)

    assert "xref.hpp" in includes
    assert "funcs.hpp" in includes


def test_find_multiple_functions(xref_source):
    tree = parse_cpp(xref_source)
    methods = find_function_bodies(tree, xref_source)

    names = {name for name, _ in methods}
    assert "show_xrefs_to" in names
    assert "show_xrefs_from" in names


def test_find_entry_functions(simple_source):
    tree = parse_cpp(simple_source)
    methods = find_function_bodies(tree, simple_source)

    names = {name for name, _ in methods}
    assert "entry_lister_t::run" in names
    assert "init" in names


def test_find_entry_base_classes(simple_source):
    tree = parse_cpp(simple_source)
    bases = find_base_classes(tree, simple_source)

    assert "entry_lister_t" in bases
    assert "plugmod_t" in bases["entry_lister_t"]
