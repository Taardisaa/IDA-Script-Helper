"""CLI entry points for the IDA SDK Workflow MCP server."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


@click.group()
def main():
    """IDA SDK API Workflow Retrieval MCP Server."""


@main.command()
@click.option(
    "--sdk-path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to an IDA SDK directory (e.g., idasdk_pro84/).",
)
@click.option(
    "--python-path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to an IDAPython directory (e.g., idapro-8.4/python/).",
)
@click.option(
    "--version",
    type=str,
    required=True,
    help="SDK version string (e.g., '84' for IDA SDK 8.4).",
)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
@click.option(
    "--max-files",
    type=int,
    default=None,
    help="Limit the number of source files to process (for testing).",
)
def build_index(
    sdk_path: Path,
    python_path: Path | None,
    version: str,
    db_path: Path,
    max_files: int | None,
):
    """Build the workflow index from an IDA SDK directory."""
    from ida_api_mcp.pipeline import build_index_pipeline

    build_index_pipeline(
        sdk_path=sdk_path,
        version=version,
        python_path=python_path,
        db_base_path=db_path,
        max_files=max_files,
        progress=click.echo,
    )


@main.command("clear-index")
@click.option(
    "--version",
    type=str,
    default=None,
    help="SDK version to clear (default: highest indexed).",
)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
def clear_index(version: str | None, db_path: Path):
    """Delete index collections for one SDK version."""
    from ida_api_mcp.indexer.store import clear_index as _clear
    from ida_api_mcp.indexer.store import get_client
    from ida_api_mcp.version_manager import (
        get_default_version,
        validate_version,
    )

    if version is None:
        version = get_default_version(db_path)
        if version is None:
            click.echo("No indexed SDK versions found.")
            return

    if not validate_version(db_path, version):
        click.echo(f"Version '{version}' is not indexed.", err=True)
        raise SystemExit(1)

    target_path = db_path / f"v{version}"
    _clear(get_client(target_path))
    click.echo(f"Cleared index collections for v{version}.")


@main.command("list-versions")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
def list_versions_cmd(db_path: Path):
    """List all indexed SDK versions."""
    from ida_api_mcp.version_manager import get_default_version, list_versions

    versions = list_versions(db_path)
    if not versions:
        click.echo("No indexed SDK versions found.")
        return

    default = get_default_version(db_path)
    for v in versions:
        marker = " (default)" if v == default else ""
        click.echo(f"  v{v}{marker}")


@main.command()
def serve():
    """Start the MCP server (stdio transport)."""
    from ida_api_mcp.server import run_server

    run_server()


@main.group()
def inspect():
    """Inspect indexed data without running MCP."""


def _resolve_version(db_path: Path, version: str | None) -> str:
    from ida_api_mcp.version_manager import (
        get_default_version,
        validate_version,
    )

    if version is None:
        version = get_default_version(db_path)
        if version is None:
            click.echo("No indexed SDK versions found.", err=True)
            raise SystemExit(1)

    if not validate_version(db_path, version):
        click.echo(f"Version '{version}' is not indexed.", err=True)
        raise SystemExit(1)

    return version


def _inspect_workflows(query: str, version: str | None, db_path: Path, n_results: int):
    """Run a workflow query against one indexed version."""
    from ida_api_mcp.indexer.search import WorkflowSearcher

    version = _resolve_version(db_path, version)

    versioned_path = db_path / f"v{version}"
    click.echo(f'Querying v{version}: "{query}"')
    click.echo("---")

    searcher = WorkflowSearcher(versioned_path)
    results = searcher.search_workflows(query, n_results=n_results)

    if not results:
        click.echo("No results found.")
        return

    for i, r in enumerate(results, 1):
        click.echo(f"=== Result {i} (trust: {r.get('trust_level', '?')}) ===")
        click.echo(r.get("display_text", "(no display text)"))
        click.echo(f"\nSource: {r.get('file_path', '?')}")
        click.echo("---")


@inspect.command("workflows")
@click.argument("query")
@click.option("--version", type=str, default=None, help="SDK version to query.")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
@click.option("--n-results", type=int, default=3, show_default=True)
def inspect_workflows_cmd(
    query: str, version: str | None, db_path: Path, n_results: int
):
    """Search for API workflows matching a task description."""
    _inspect_workflows(query, version, db_path, n_results)


@inspect.command("info")
@click.option("--version", type=str, default=None, help="SDK version to inspect.")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
def inspect_info_cmd(version: str | None, db_path: Path):
    """Show index metadata for one SDK version."""
    from ida_api_mcp.indexer.store import get_client, get_index_info

    version = _resolve_version(db_path, version)
    info = get_index_info(get_client(db_path / f"v{version}"))

    click.echo(f"SDK version    : {version}")
    click.echo(f"Indexed at     : {info['indexed_at']}")
    click.echo(f"Workflows      : {info['workflow_count']}")
    click.echo(f"API docs       : {info['api_doc_count']}")


@inspect.command("api-doc")
@click.argument("name")
@click.option("--version", type=str, default=None, help="SDK version to query.")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
@click.option("--n-results", type=int, default=5, show_default=True)
def inspect_api_doc_cmd(name: str, version: str | None, db_path: Path, n_results: int):
    """Look up API documentation entries."""
    from ida_api_mcp.indexer.search import WorkflowSearcher

    version = _resolve_version(db_path, version)
    searcher = WorkflowSearcher(db_path / f"v{version}")
    results = searcher.get_api_doc(name, n_results=n_results)

    if not results:
        click.echo(f"No API documentation found for '{name}'.")
        return

    for result in results:
        click.echo(f"## {result.get('name', '?')}")
        if result.get("brief"):
            click.echo(result["brief"])
        if result.get("signature"):
            click.echo(f"Signature: {result['signature']}")
        if result.get("header_file"):
            click.echo(f"Header: {result['header_file']}")
        click.echo(f"Used in {result.get('workflow_count', 0)} extracted workflow(s)")
        click.echo("---")


@inspect.command("related")
@click.argument("name")
@click.option("--version", type=str, default=None, help="SDK version to query.")
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
def inspect_related_cmd(name: str, version: str | None, db_path: Path):
    """Find APIs commonly used alongside a given API."""
    from ida_api_mcp.indexer.search import WorkflowSearcher

    version = _resolve_version(db_path, version)
    searcher = WorkflowSearcher(db_path / f"v{version}")
    result = searcher.list_related_apis(name)

    if not result["related"]:
        click.echo(f"No related APIs found for '{name}'.")
        return

    click.echo(
        f"APIs commonly used with {result['queried']} "
        f"(found in {result['workflow_count']} workflow(s)):"
    )
    for item in result["related"]:
        click.echo(
            f"  {item['api']}: co-occurs in {item['co_occurrence_count']} workflow(s)"
        )


if __name__ == "__main__":
    main()
