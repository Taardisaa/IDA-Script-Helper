"""Parse Doxygen-style comments from IDA SDK header files.

Despite the module name (kept for architectural consistency with the plan),
this parses Doxygen comments directly from C++ headers rather than HTML,
since the IDA SDK ships headers with inline Doxygen comments but no
pre-built HTML documentation.
"""

from __future__ import annotations

import re
from pathlib import Path

from ida_sdk_workflow_mcp.extractor.models import HeaderApiDoc

# Pattern: optional /// comment lines, followed by idaman <ret> ida_export <name>(<params>);
_IDAMAN_FUNC_RE = re.compile(
    r"((?:///[^\n]*\n)*)"       # group 1: optional /// comment block
    r"\s*"
    r"idaman\s+"                # idaman keyword
    r"(.*?)\s*"                 # group 2: return type (handles pointers like func_t *)
    r"ida_export\s+"            # ida_export keyword
    r"(\w+)"                    # group 3: function name
    r"\s*\(([^)]*)\)"          # group 4: parameter list
    r"\s*;",
    re.MULTILINE,
)

# Pattern: /// comment block followed by struct/class definition
_STRUCT_CLASS_RE = re.compile(
    r"((?:///[^\n]*\n)+)"       # group 1: /// comment block (at least one line)
    r"\s*"
    r"(class|struct)\s+"        # group 2: kind
    r"(\w+)"                    # group 3: name
    r"\s*"
    r"(?::\s*[^{]+)?"          # optional base class clause
    r"\s*\{",                   # opening brace
    re.MULTILINE,
)

# Param doc pattern inside /// comments: \param name description
_PARAM_RE = re.compile(r"\\param\s+(\w+)\s+(.*)")

# Return doc pattern: \return description
_RETURN_RE = re.compile(r"\\return\s+(.*)")


def _parse_comment_block(comment: str) -> tuple[str, list[tuple[str, str]], str]:
    """Parse a /// comment block into (brief, params, return_desc)."""
    lines = []
    params: list[tuple[str, str]] = []
    return_desc = ""

    for line in comment.splitlines():
        # Strip leading /// and whitespace
        stripped = re.sub(r"^\s*///\s?", "", line)

        param_match = _PARAM_RE.match(stripped)
        if param_match:
            params.append((param_match.group(1), param_match.group(2).strip()))
            continue

        return_match = _RETURN_RE.match(stripped)
        if return_match:
            return_desc = return_match.group(1).strip()
            continue

        # Skip defgroup and other non-brief directives
        if stripped.startswith("\\") and not stripped.startswith("\\brief"):
            continue

        stripped = re.sub(r"^\\brief\s+", "", stripped)
        lines.append(stripped)

    brief = " ".join(lines).strip()
    # Collapse multiple spaces
    brief = re.sub(r"\s+", " ", brief)
    return brief, params, return_desc


def parse_header_file(path: Path) -> list[HeaderApiDoc]:
    """Parse an IDA SDK header file for API documentation.

    Extracts:
    - idaman ... ida_export function declarations with preceding /// comments
    - struct/class definitions with preceding /// comments
    """
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    header_name = path.name
    docs: list[HeaderApiDoc] = []

    # Extract idaman functions
    for m in _IDAMAN_FUNC_RE.finditer(content):
        comment = m.group(1)
        ret_type = m.group(2).strip()
        func_name = m.group(3)
        param_str = m.group(4).strip()
        signature = f"{ret_type} {func_name}({param_str})"

        brief, params, return_desc = _parse_comment_block(comment)

        docs.append(HeaderApiDoc(
            name=func_name,
            brief=brief,
            signature=signature,
            header_file=header_name,
            kind="function",
            params=params,
            return_desc=return_desc,
        ))

    # Extract struct/class definitions
    for m in _STRUCT_CLASS_RE.finditer(content):
        comment = m.group(1)
        kind = m.group(2)
        name = m.group(3)

        brief, _, _ = _parse_comment_block(comment)

        docs.append(HeaderApiDoc(
            name=name,
            brief=brief,
            signature=f"{kind} {name}",
            header_file=header_name,
            kind=kind,
        ))

    return docs
