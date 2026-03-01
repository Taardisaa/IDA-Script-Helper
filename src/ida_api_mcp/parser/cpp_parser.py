"""Tree-sitter based C++ parser for extracting AST information."""

from __future__ import annotations

from tree_sitter import Node, Tree
from tree_sitter_languages import get_language, get_parser

CPP_LANGUAGE = get_language("cpp")

# Pre-compiled queries for common AST patterns

# Find #include directives: #include <ida.hpp> or #include "ida.hpp"
INCLUDE_QUERY = CPP_LANGUAGE.query("""
(preproc_include
  path: [(system_lib_string) (string_literal)] @include_path)
""")

# Find function definitions with bodies
FUNCTION_DEF_QUERY = CPP_LANGUAGE.query("""
(function_definition
  declarator: (_) @declarator
  body: (compound_statement) @body)
""")

# Find class/struct definitions with base classes
CLASS_DEF_QUERY = CPP_LANGUAGE.query("""
[
  (class_specifier
    name: (type_identifier) @class_name
    (base_class_clause
      (type_identifier) @base_class)?)
  (struct_specifier
    name: (type_identifier) @struct_name
    (base_class_clause
      (type_identifier) @base_class)?)
]
""")


def parse_cpp(source: bytes) -> Tree:
    """Parse C++ source code into a tree-sitter AST."""
    parser = get_parser("cpp")
    return parser.parse(source)


def get_node_text(node: Node, source: bytes) -> str:
    """Extract the text of an AST node from the source."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def find_includes(tree: Tree, source: bytes) -> list[str]:
    """Extract #include paths, returning a list of header names.

    e.g., ["ida.hpp", "funcs.hpp", "kernwin.hpp"]
    """
    includes: list[str] = []
    captures = INCLUDE_QUERY.captures(tree.root_node)

    for node, _name in captures:
        text = get_node_text(node, source)
        # Strip angle brackets or quotes: <ida.hpp> -> ida.hpp, "ida.hpp" -> ida.hpp
        text = text.strip('<>"')
        includes.append(text)

    return includes


def find_function_bodies(tree: Tree, source: bytes) -> list[tuple[str, Node]]:
    """Find all function definitions, returning (function_name, body_node) pairs.

    Handles regular functions, class methods (Type::method), and
    declarators with pointers/references.
    """
    results = []
    captures = FUNCTION_DEF_QUERY.captures(tree.root_node)

    declarators = [(node, name) for node, name in captures if name == "declarator"]
    bodies = [(node, name) for node, name in captures if name == "body"]

    for (decl_node, _), (body_node, _) in zip(declarators, bodies):
        func_name = _extract_function_name(decl_node, source)
        if func_name:
            results.append((func_name, body_node))

    return results


def _extract_function_name(declarator: Node, source: bytes) -> str | None:
    """Extract the function name from a declarator node.

    Handles:
    - Simple: void func(...)
    - Qualified: bool Type::method(...)
    - Pointer return: func_t *get_func(...)
    - Reference: const char &get_name(...)
    """
    # For function_declarator, the first child is the actual name/qualified name
    # For pointer_declarator wrapping function_declarator, we need to go deeper
    node = declarator

    # Unwrap pointer/reference declarators
    while node.type in ("pointer_declarator", "reference_declarator"):
        for child in node.children:
            if child.type == "function_declarator":
                node = child
                break
        else:
            return None

    if node.type == "function_declarator":
        name_child = node.child_by_field_name("declarator")
        if name_child is None:
            return None
        if name_child.type == "qualified_identifier":
            # Type::method — return just method name
            scope_node = name_child.child_by_field_name("scope")
            name_node = name_child.child_by_field_name("name")
            if scope_node and name_node:
                return f"{get_node_text(scope_node, source)}::{get_node_text(name_node, source)}"
            elif name_node:
                return get_node_text(name_node, source)
        elif name_child.type == "identifier":
            return get_node_text(name_child, source)
        elif name_child.type == "destructor_name":
            return get_node_text(name_child, source)
        elif name_child.type == "field_identifier":
            return get_node_text(name_child, source)
        # Nested pointer declarator
        elif name_child.type == "pointer_declarator":
            return _extract_function_name(name_child, source)

    if node.type == "identifier":
        return get_node_text(node, source)

    return None


def find_base_classes(tree: Tree, source: bytes) -> dict[str, list[str]]:
    """Find class/struct definitions and their base classes.

    Returns a mapping of class_name -> [base_class_names].
    """
    captures = CLASS_DEF_QUERY.captures(tree.root_node)

    result: dict[str, list[str]] = {}
    current_class: str | None = None

    for node, name in captures:
        if name in ("class_name", "struct_name"):
            current_class = get_node_text(node, source)
            if current_class not in result:
                result[current_class] = []
        elif name == "base_class" and current_class is not None:
            result[current_class].append(get_node_text(node, source))

    return result
