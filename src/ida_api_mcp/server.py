"""MCP server exposing IDA SDK API workflow retrieval tools."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from ida_api_mcp.config import Config
from ida_api_mcp.indexer.search import WorkflowSearcher
from ida_api_mcp.version_manager import (
    get_default_version,
    list_versions,
    validate_version,
)

# All logging must go to stderr — stdout is reserved for MCP stdio transport
logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

mcp = FastMCP("ida-api-mcp")

# State: active version and lazy-initialized searcher
_config = Config()
_active_version: str | None = None
_searcher: WorkflowSearcher | None = None


def _get_searcher() -> WorkflowSearcher:
    """Get or create a searcher for the active version.

    On first call, auto-selects the highest indexed version.
    """
    global _searcher, _active_version
    if _searcher is not None:
        return _searcher

    if _active_version is None:
        _active_version = get_default_version(_config.db_base_path)

    if _active_version is None:
        raise RuntimeError(
            "No indexed SDK versions found. "
            "Run: ida-api-mcp-admin build-index --sdk-path <path> --version <ver>"
        )

    db_path = _config.db_base_path / f"v{_active_version}"
    _searcher = WorkflowSearcher(db_path)
    return _searcher


def _get_active_or_default_version() -> str | None:
    """Return active version or auto-selected highest indexed version."""
    global _active_version
    if _active_version is None:
        _active_version = get_default_version(_config.db_base_path)
    return _active_version


@mcp.tool()
def get_versions() -> str:
    """List all indexed IDA SDK versions and show which is currently active.

    Returns a list of available SDK versions with the active one marked.
    """
    versions = list_versions(_config.db_base_path)
    if not versions:
        return "No indexed SDK versions found."

    active = _active_version or get_default_version(_config.db_base_path)
    lines = ["Indexed IDA SDK versions:"]
    for v in versions:
        marker = " (active)" if v == active else ""
        lines.append(f"  v{v}{marker}")
    return "\n".join(lines)


@mcp.tool()
def select_version(version: str) -> str:
    """Switch to a specific indexed IDA SDK version.

    Args:
        version: The version string (e.g., "84" for IDA SDK 8.4)
    """
    global _active_version, _searcher

    if not validate_version(_config.db_base_path, version):
        available = list_versions(_config.db_base_path)
        return (
            f"Version '{version}' is not indexed. "
            f"Available: {', '.join(available) if available else 'none'}"
        )

    _active_version = version
    _searcher = None  # Force re-initialization
    return f"Switched to IDA SDK v{version}."


@mcp.tool()
def get_workflows(task_description: str) -> str:
    """Search for IDA SDK API workflows matching a task description.

    Returns ranked workflow call chains showing the correct API call
    sequence for accomplishing the described task. Each result includes
    ordered API calls with data-flow dependencies and source code.

    Args:
        task_description: Natural language description of what you want
                          to accomplish, e.g. "get the function at an address"
    """
    searcher = _get_searcher()
    results = searcher.search_workflows(task_description, n_results=3)

    if not results:
        return "No matching workflows found for this task description."

    output_parts = []
    for i, r in enumerate(results, 1):
        output_parts.append(f"=== Result {i} (trust: {r.get('trust_level', '?')}) ===")
        output_parts.append(r.get("display_text", "(no display text)"))
        snippet = r.get("source_snippet", "")
        if snippet:
            output_parts.append(f"\nSource code:\n```cpp\n{snippet}\n```")
        output_parts.append("")

    return "\n".join(output_parts)


@mcp.tool()
def get_api_doc(name: str) -> str:
    """Look up IDA SDK API documentation for a function, struct, or class.

    Supports fuzzy and partial matching — no fully qualified name needed.

    Args:
        name: Function name, struct name, or keyword to search for.
              Examples: "get_func", "func_t", "xrefblk_t"
    """
    searcher = _get_searcher()
    results = searcher.get_api_doc(name, n_results=5)

    if not results:
        return f"No API documentation found for '{name}'."

    output_parts = []
    for r in results:
        api_name = r.get("name", "?")
        brief = r.get("brief", "")
        sig = r.get("signature", "")
        header = r.get("header_file", "")
        wf_count = r.get("workflow_count", 0)
        example = r.get("example_file", "")

        output_parts.append(f"## {api_name}")
        if brief:
            output_parts.append(f"{brief}")
        if sig:
            output_parts.append(f"Signature: `{sig}`")
        if header:
            output_parts.append(f"Header: {header}")
        output_parts.append(f"Used in {wf_count} extracted workflow(s)")
        if example:
            output_parts.append(f"Example: {example}")
        output_parts.append("")

    return "\n".join(output_parts)


@mcp.tool()
def list_related_apis(name: str) -> str:
    """Find IDA SDK APIs commonly used alongside a given function or type.

    Returns co-occurring APIs based on real usage patterns in SDK source code.

    Args:
        name: An IDA SDK function or type name, e.g. "get_func"
    """
    searcher = _get_searcher()
    result = searcher.list_related_apis(name)

    if not result["related"]:
        return f"No related APIs found for '{name}'."

    output_parts = [
        f"APIs commonly used with {result['queried']} "
        f"(found in {result['workflow_count']} workflow(s)):",
        "",
    ]
    for item in result["related"]:
        output_parts.append(
            f"- {item['api']}: co-occurs in {item['co_occurrence_count']} workflow(s)"
        )

    return "\n".join(output_parts)


@mcp.tool()
def get_index_info() -> str:
    """Return metadata about the currently indexed SDK version.

    Shows version, build timestamp, and counts for workflows and API docs.
    """
    from ida_api_mcp.indexer.store import get_client
    from ida_api_mcp.indexer.store import get_index_info as _get_info

    version = _get_active_or_default_version()
    if version is None:
        return "No indexed SDK versions found."

    info = _get_info(get_client(_config.db_base_path / f"v{version}"))

    if info["workflow_count"] == 0 and info["api_doc_count"] == 0:
        return f"Index for SDK v{version} is empty. Run initialize_index() to build it."

    return (
        f"SDK version    : v{version}\n"
        f"Indexed at     : {info['indexed_at']}\n"
        f"Workflows      : {info['workflow_count']}\n"
        f"API docs       : {info['api_doc_count']}"
    )


@mcp.tool()
def clear_index(version: str = "") -> str:
    """Delete index collections for one indexed SDK version.

    Args:
        version: Optional SDK version string. If omitted, clears the active
                 version (or highest indexed version if none selected).
    """
    from ida_api_mcp.indexer.store import clear_index as _clear
    from ida_api_mcp.indexer.store import get_client

    global _active_version, _searcher

    target_version = version.strip() if version else _get_active_or_default_version()
    if target_version is None:
        return "No indexed SDK versions found."

    if not validate_version(_config.db_base_path, target_version):
        available = list_versions(_config.db_base_path)
        return (
            f"Version '{target_version}' is not indexed. "
            f"Available: {', '.join(available) if available else 'none'}"
        )

    _clear(get_client(_config.db_base_path / f"v{target_version}"))

    if _active_version == target_version:
        _searcher = None

    return (
        f"Index for SDK v{target_version} cleared. Run initialize_index() to rebuild."
    )


@mcp.tool()
def initialize_index(
    sdk_path: str,
    version: str,
    python_path: str = "",
    max_files: int = 0,
) -> str:
    """Build the IDA SDK workflow index.

    Args:
        sdk_path: Absolute path to an IDA SDK directory.
        version: SDK version string (e.g., "84").
        python_path: Optional path to IDAPython directory.
        max_files: Optional file limit for testing; use 0 for no limit.
    """
    from ida_api_mcp.pipeline import build_index_pipeline

    global _active_version, _searcher

    sdk_root = Path(sdk_path)
    py_root = Path(python_path) if python_path else None
    file_limit = max_files if max_files > 0 else None
    messages: list[str] = []

    try:
        build_index_pipeline(
            sdk_path=sdk_root,
            version=version,
            python_path=py_root,
            db_base_path=_config.db_base_path,
            max_files=file_limit,
            progress=messages.append,
        )
    except Exception as exc:
        return f"Failed to build index: {exc}"

    _active_version = version
    _searcher = None
    return "\n".join(messages)


def run_server():
    """Start the MCP server with stdio transport."""
    mcp.run(transport="stdio")
