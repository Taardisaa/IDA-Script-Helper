"""Parse IDAPython SWIG-generated stub files for API documentation.

Uses Python's ast module to extract function definitions, class definitions,
and their docstrings from ida_*.py stub files. Docstrings follow the SWIG
format with @param / @return annotations.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from ida_sdk_workflow_mcp.extractor.models import HeaderApiDoc

logger = logging.getLogger(__name__)

# Modules to scan for API names (beyond ida_*.py)
_EXTRA_MODULES = ("idautils.py", "idc.py")

# SWIG internal helpers — skip these
_SKIP_PREFIXES = ("_swig_", "_SwigNonDynamic", "SwigPyIterator")


def _parse_swig_docstring(
    docstring: str,
) -> tuple[str, str, list[tuple[str, str]], str]:
    """Parse a SWIG-style docstring.

    Returns:
        (brief, signature, params, return_desc)
    """
    if not docstring:
        return "", "", [], ""

    lines = docstring.strip().splitlines()
    signature = ""
    brief_lines: list[str] = []
    params: list[tuple[str, str]] = []
    return_desc = ""

    # First non-empty line is typically the signature: func_name(args) -> type
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1

    if i < len(lines):
        first_line = lines[i].strip()
        # Check if it looks like a signature: name(... -> ...  or  name(...)
        if "(" in first_line:
            signature = first_line
            i += 1

    # Remaining lines: brief description, @param, @return
    for line in lines[i:]:
        stripped = line.strip()
        if not stripped:
            continue

        param_match = re.match(r"@param\s+(\w+):\s*(.*)", stripped)
        if param_match:
            param_name = param_match.group(1)
            param_desc = param_match.group(2).strip()
            # Strip C++ type hints like "(C++: ea_t)"
            param_desc = re.sub(r"\(C\+\+:\s*\w[\w\s*&:,]*\)\s*", "", param_desc)
            params.append((param_name, param_desc.strip()))
            continue

        return_match = re.match(r"@return:\s*(.*)", stripped)
        if return_match:
            return_desc = return_match.group(1).strip()
            continue

        # Skip lines that start with @ but aren't @param/@return
        if stripped.startswith("@"):
            continue

        brief_lines.append(stripped)

    brief = " ".join(brief_lines).strip()
    # Collapse multiple spaces
    brief = re.sub(r"\s+", " ", brief)

    return brief, signature, params, return_desc


def _should_skip(name: str) -> bool:
    """Return True if this name is a SWIG internal we should skip."""
    if name.startswith("_"):
        return True
    for prefix in _SKIP_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def parse_stub_file(path: Path) -> list[HeaderApiDoc]:
    """Parse a single IDAPython SWIG stub file for API documentation.

    Extracts top-level functions and classes with their docstrings.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Could not read %s: %s", path, e)
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        logger.warning("Could not parse %s: %s", path, e)
        return []

    module_name = path.stem  # e.g., "ida_funcs"
    docs: list[HeaderApiDoc] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            if _should_skip(node.name):
                continue

            docstring = ast.get_docstring(node, clean=True) or ""
            brief, signature, params, return_desc = _parse_swig_docstring(docstring)

            if not signature:
                # Build from function def
                args = []
                for arg in node.args.args:
                    if arg.arg != "self":
                        args.append(arg.arg)
                signature = f"{node.name}({', '.join(args)})"

            docs.append(HeaderApiDoc(
                name=node.name,
                brief=brief,
                signature=signature,
                header_file=module_name,
                kind="function",
                params=params,
                return_desc=return_desc,
            ))

        elif isinstance(node, ast.ClassDef):
            if _should_skip(node.name):
                continue

            docstring = ast.get_docstring(node, clean=True) or ""
            # For classes, the brief is usually in the docstring directly
            brief = ""
            if docstring:
                # Strip "Proxy of C++ ... class." prefix if present
                cleaned = re.sub(
                    r"Proxy of C\+\+\s+\S+\s+class\.\s*", "", docstring
                ).strip()
                if cleaned:
                    brief = cleaned.split("\n")[0].strip()
                else:
                    # Use the proxy line itself as brief
                    brief = docstring.split("\n")[0].strip()

            docs.append(HeaderApiDoc(
                name=node.name,
                brief=brief,
                signature=f"class {node.name}",
                header_file=module_name,
                kind="class",
            ))

            # Also extract methods from classes
            for item in ast.iter_child_nodes(node):
                if isinstance(item, ast.FunctionDef):
                    if _should_skip(item.name) or item.name.startswith("__"):
                        continue
                    method_doc = ast.get_docstring(item, clean=True) or ""
                    m_brief, m_sig, m_params, m_ret = _parse_swig_docstring(method_doc)
                    if not m_sig:
                        args = [a.arg for a in item.args.args if a.arg != "self"]
                        m_sig = f"{node.name}.{item.name}({', '.join(args)})"

                    docs.append(HeaderApiDoc(
                        name=f"{node.name}.{item.name}",
                        brief=m_brief,
                        signature=m_sig,
                        header_file=module_name,
                        kind="method",
                        params=m_params,
                        return_desc=m_ret,
                    ))

    return docs


def build_api_names_from_stubs(python_dir: Path) -> tuple[set[str], dict[str, set[str]]]:
    """Scan all IDAPython stubs and return known API function names.

    Args:
        python_dir: Path to the IDAPython directory (contains '3/' subdirectory).

    Returns:
        Tuple of:
        - flat set of all known API function names
        - dict mapping module_name -> set of function names in that module
    """
    all_names: set[str] = set()
    module_apis: dict[str, set[str]] = {}

    stubs_dir = python_dir / "3"
    if not stubs_dir.is_dir():
        logger.warning("Stubs directory not found: %s", stubs_dir)
        return all_names, module_apis

    # Scan ida_*.py stubs
    for stub_path in sorted(stubs_dir.glob("ida_*.py")):
        module_name = stub_path.stem
        names = _extract_function_names(stub_path)
        all_names.update(names)
        module_apis[module_name] = names

    # Also scan idautils.py and idc.py
    for extra in _EXTRA_MODULES:
        extra_path = stubs_dir / extra
        if extra_path.is_file():
            module_name = extra_path.stem
            names = _extract_function_names(extra_path)
            all_names.update(names)
            module_apis[module_name] = names

    logger.info(
        "Built Python API name set: %d functions from %d modules",
        len(all_names),
        len(module_apis),
    )
    return all_names, module_apis


def _extract_function_names(path: Path) -> set[str]:
    """Extract top-level function and class names from a Python file using ast.

    Class names are included because IDAPython examples frequently call
    constructors via module-qualified syntax (e.g., ``ida_gdl.FlowChart(f)``).
    """
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return set()

    names: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef) and not _should_skip(node.name):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef) and not _should_skip(node.name):
            names.add(node.name)
    return names
