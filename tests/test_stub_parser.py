"""Tests for the IDAPython SWIG stub parser."""

from pathlib import Path

from ida_api_mcp.parser.stub_parser import (
    build_api_names_from_stubs,
    parse_stub_file,
)


def test_parse_stub_file_functions(fixtures_dir):
    """Test that free functions are extracted from a stub file."""
    docs = parse_stub_file(fixtures_dir / "sample_stub.py")

    func_docs = [d for d in docs if d.kind == "function"]
    func_names = {d.name for d in func_docs}

    assert "get_func" in func_names
    assert "get_func_name" in func_names
    assert "get_func_qty" in func_names
    assert "add_func" in func_names
    assert "del_func" in func_names


def test_parse_stub_file_docstring_extraction(fixtures_dir):
    """Test that docstrings are correctly parsed."""
    docs = parse_stub_file(fixtures_dir / "sample_stub.py")

    get_func_doc = next(d for d in docs if d.name == "get_func")
    assert "Get pointer to function structure by address" in get_func_doc.brief
    assert get_func_doc.signature == "get_func(ea) -> func_t"
    assert get_func_doc.header_file == "sample_stub"
    assert get_func_doc.kind == "function"


def test_parse_stub_file_params(fixtures_dir):
    """Test that @param annotations are extracted."""
    docs = parse_stub_file(fixtures_dir / "sample_stub.py")

    get_func_doc = next(d for d in docs if d.name == "get_func")
    assert len(get_func_doc.params) == 1
    param_name, param_desc = get_func_doc.params[0]
    assert param_name == "ea"
    assert "any address in a function" in param_desc


def test_parse_stub_file_return(fixtures_dir):
    """Test that @return annotations are extracted."""
    docs = parse_stub_file(fixtures_dir / "sample_stub.py")

    get_func_doc = next(d for d in docs if d.name == "get_func")
    assert "ptr to a function or nullptr" in get_func_doc.return_desc


def test_parse_stub_file_classes(fixtures_dir):
    """Test that classes are extracted."""
    docs = parse_stub_file(fixtures_dir / "sample_stub.py")

    class_docs = [d for d in docs if d.kind == "class"]
    assert len(class_docs) == 1
    assert class_docs[0].name == "func_t"
    assert class_docs[0].signature == "class func_t"


def test_parse_stub_file_methods(fixtures_dir):
    """Test that class methods are extracted."""
    docs = parse_stub_file(fixtures_dir / "sample_stub.py")

    method_docs = [d for d in docs if d.kind == "method"]
    method_names = {d.name for d in method_docs}
    assert "func_t.is_far" in method_names


def test_parse_stub_file_skips_swig_internals(fixtures_dir):
    """Test that SWIG internal functions are skipped."""
    docs = parse_stub_file(fixtures_dir / "sample_stub.py")

    names = {d.name for d in docs}
    # _swig_* and _ prefixed names should be skipped
    for name in names:
        assert not name.startswith("_swig_")
        assert not name.startswith("_")


def test_build_api_names_from_stubs_with_fixture(fixtures_dir, tmp_path):
    """Test build_api_names_from_stubs with a minimal directory layout."""
    # Create a mock directory structure: python_dir/3/ida_funcs.py
    stubs_dir = tmp_path / "3"
    stubs_dir.mkdir()

    # Copy fixture as ida_funcs.py
    import shutil
    shutil.copy(fixtures_dir / "sample_stub.py", stubs_dir / "ida_funcs.py")

    all_names, module_apis = build_api_names_from_stubs(tmp_path)

    assert "get_func" in all_names
    assert "get_func_name" in all_names
    assert "ida_funcs" in module_apis
    assert "get_func" in module_apis["ida_funcs"]
