"""CLI entry points for the IDA SDK Workflow MCP server."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from ida_sdk_workflow_mcp.config import Config

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
    help="Limit the number of C++ files to process (for testing).",
)
def build_index(sdk_path: Path, version: str, db_path: Path, max_files: int | None):
    """Build the workflow index from an IDA SDK directory."""
    from ida_sdk_workflow_mcp.collector.doc_source import collect_api_docs
    from ida_sdk_workflow_mcp.collector.sdk_source import (
        build_known_api_names,
        enumerate_cpp_files,
        validate_sdk_root,
    )
    from ida_sdk_workflow_mcp.extractor.call_chain import extract_workflows_from_source
    from ida_sdk_workflow_mcp.indexer.store import (
        build_api_docs_index,
        build_workflow_index,
        get_client,
    )

    if not validate_sdk_root(sdk_path):
        click.echo(f"Error: {sdk_path} does not look like an IDA SDK tree.", err=True)
        raise SystemExit(1)

    config = Config(
        sdk_path=sdk_path,
        version=version,
        db_base_path=db_path,
        max_files=max_files,
    )

    click.echo(f"Using IDA SDK at: {sdk_path}")
    click.echo(f"Version: v{version}")

    # Step 1: Build known API names from headers
    click.echo("Scanning headers for known API names...")
    known_api_names = build_known_api_names(sdk_path, config)
    click.echo(f"Found {len(known_api_names)} known API functions")

    # Step 2: Enumerate C++ source files
    click.echo("Enumerating C++ source files...")
    source_files = enumerate_cpp_files(sdk_path, config)
    click.echo(f"Found {len(source_files)} C++ files to process")

    # Step 3: Extract workflows
    click.echo("Extracting workflows...")
    all_workflows = []
    for i, sf in enumerate(source_files):
        if (i + 1) % 100 == 0:
            click.echo(f"  Processed {i + 1}/{len(source_files)} files...")
        workflows = extract_workflows_from_source(sf, known_api_names, config)
        all_workflows.extend(workflows)
    click.echo(f"Extracted {len(all_workflows)} workflows")

    # Step 4: Collect API docs from headers
    click.echo("Collecting API documentation from headers...")
    api_docs = collect_api_docs(sdk_path, config)
    click.echo(f"Collected {len(api_docs)} API doc entries")

    # Step 5: Index into ChromaDB
    click.echo("Building ChromaDB index...")
    client = get_client(config.db_path)
    build_workflow_index(client, all_workflows)
    build_api_docs_index(client, all_workflows, api_docs)
    click.echo(f"Index built at: {config.db_path}")
    click.echo("Done!")


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
    from ida_sdk_workflow_mcp.version_manager import get_default_version, list_versions

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
    from ida_sdk_workflow_mcp.server import run_server

    run_server()


@main.command()
@click.argument("query")
@click.option(
    "--version",
    type=str,
    default=None,
    help="SDK version to query (default: highest).",
)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default="data/chroma_db",
    show_default=True,
    help="Base path for ChromaDB storage.",
)
@click.option(
    "--n-results",
    type=int,
    default=3,
    show_default=True,
    help="Number of results to return.",
)
def inspect(query: str, version: str | None, db_path: Path, n_results: int):
    """Test a query against the index without running MCP."""
    from ida_sdk_workflow_mcp.indexer.search import WorkflowSearcher
    from ida_sdk_workflow_mcp.version_manager import get_default_version, validate_version

    if version is None:
        version = get_default_version(db_path)
        if version is None:
            click.echo("No indexed SDK versions found.", err=True)
            raise SystemExit(1)

    if not validate_version(db_path, version):
        click.echo(f"Version '{version}' is not indexed.", err=True)
        raise SystemExit(1)

    versioned_path = db_path / f"v{version}"
    click.echo(f"Querying v{version}: \"{query}\"")
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


if __name__ == "__main__":
    main()
