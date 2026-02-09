"""Parse Python source files using the ast module.

Extracts imports, function bodies, and metadata from IDAPython example scripts.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path


def parse_python(source: bytes) -> ast.Module:
    """Parse Python source into an AST."""
    return ast.parse(source)


def find_imports(tree: ast.Module) -> dict[str, str]:
    """Extract import mappings from an AST.

    Returns a dict mapping locally-available names to their module of origin:
    - ``import ida_funcs``         → ``{"ida_funcs": "ida_funcs"}``
    - ``from ida_funcs import get_func`` → ``{"get_func": "ida_funcs"}``
    - ``import ida_funcs as f``    → ``{"f": "ida_funcs"}``
    """
    imports: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                imports[local_name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                imports[local_name] = module

    return imports


def find_function_bodies(
    tree: ast.Module, source: bytes,
) -> list[tuple[str, ast.AST]]:
    """Return (function_name, function_node) pairs from the module.

    Includes:
    - All top-level ``def`` statements
    - Methods inside top-level classes (named ``ClassName.method_name``)
    - A pseudo-function ``<module>`` for top-level code (statements not inside
      any function/class), so script-style examples get processed too.
    """
    results: list[tuple[str, ast.AST]] = []

    for node in ast.iter_child_nodes(tree):
        # Top-level function defs
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            results.append((node.name, node))

        # Methods inside top-level classes
        elif isinstance(node, ast.ClassDef):
            for item in ast.iter_child_nodes(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    results.append((f"{node.name}.{item.name}", item))

    # Build a pseudo-function for module-level statements
    # (everything that is not a function/class def or import)
    module_stmts = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        module_stmts.append(node)

    if module_stmts:
        # Create a wrapper module node containing just the top-level statements
        pseudo = ast.Module(body=module_stmts, type_ignores=[])
        results.append(("<module>", pseudo))

    return results


def extract_metadata(source: str) -> dict:
    """Parse structured metadata from an IDAPython example's docstring.

    IDA examples use a YAML-ish format in the module docstring::

        \"\"\"
        summary: enumerate file imports

        description:
          Using the API to enumerate file imports.

        keywords: functions, flowchart
        \"\"\"

    Returns a dict with keys like ``summary``, ``description``, ``keywords``.
    """
    metadata: dict[str, str] = {}

    # Extract the module docstring
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return metadata

    docstring = ast.get_docstring(tree)
    if not docstring:
        return metadata

    # Parse key: value pairs
    current_key = None
    current_lines: list[str] = []

    for line in docstring.splitlines():
        # Check for a top-level key: value
        key_match = re.match(r"^(\w+):\s*(.*)", line)
        if key_match and not line.startswith(" "):
            # Save previous key
            if current_key is not None:
                metadata[current_key] = "\n".join(current_lines).strip()
            current_key = key_match.group(1)
            value = key_match.group(2).strip()
            current_lines = [value] if value else []
        elif current_key is not None:
            # Continuation line (indented)
            current_lines.append(line.strip())

    # Save last key
    if current_key is not None:
        metadata[current_key] = "\n".join(current_lines).strip()

    return metadata
