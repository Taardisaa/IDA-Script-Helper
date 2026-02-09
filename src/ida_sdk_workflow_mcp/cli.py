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
        python_path=python_path,
        version=version,
        db_base_path=db_path,
        max_files=max_files,
    )

    click.echo(f"Using IDA SDK at: {sdk_path}")
    click.echo(f"Version: v{version}")

    # Step 1: Build known API names from C++ headers
    click.echo("Scanning headers for known API names...")
    known_api_names = build_known_api_names(sdk_path, config)
    click.echo(f"Found {len(known_api_names)} known C++ API functions")

    # Step 2: Enumerate C++ source files
    click.echo("Enumerating C++ source files...")
    source_files = enumerate_cpp_files(sdk_path, config)
    click.echo(f"Found {len(source_files)} C++ files to process")

    # Step 3: Extract C++ workflows
    click.echo("Extracting C++ workflows...")
    all_workflows = []
    for i, sf in enumerate(source_files):
        if (i + 1) % 100 == 0:
            click.echo(f"  Processed {i + 1}/{len(source_files)} files...")
        workflows = extract_workflows_from_source(sf, known_api_names, config)
        all_workflows.extend(workflows)
    click.echo(f"Extracted {len(all_workflows)} C++ workflows")

    # Step 4: Collect API docs from C++ headers
    click.echo("Collecting API documentation from headers...")
    api_docs = collect_api_docs(sdk_path, config)
    click.echo(f"Collected {len(api_docs)} C++ API doc entries")

    # Step 5: Python pipeline (if --python-path provided)
    if python_path:
        _run_python_pipeline(
            python_path, config, known_api_names, all_workflows, api_docs,
        )

    # Step 6: Index into ChromaDB
    click.echo("Building ChromaDB index...")
    client = get_client(config.db_path)

    # Build api_briefs dict from all docs for workflow embedding enrichment
    api_briefs = {doc.name: doc.brief for doc in api_docs if doc.brief}

    build_workflow_index(client, all_workflows, api_briefs=api_briefs)
    build_api_docs_index(client, all_workflows, api_docs)
    click.echo(f"Index built at: {config.db_path}")
    click.echo("Done!")


def _run_python_pipeline(
    python_path: Path,
    config: Config,
    known_api_names: set[str],
    all_workflows: list,
    api_docs: list,
) -> None:
    """Run the IDAPython collection/extraction pipeline."""
    from ida_sdk_workflow_mcp.collector.python_source import (
        collect_python_api_docs,
        enumerate_python_examples,
        validate_python_dir,
    )
    from ida_sdk_workflow_mcp.extractor.python_call_chain import (
        extract_workflows_from_python,
    )
    from ida_sdk_workflow_mcp.parser.stub_parser import build_api_names_from_stubs

    if not validate_python_dir(python_path):
        click.echo(
            f"Warning: {python_path} does not look like an IDAPython directory, skipping.",
            err=True,
        )
        return

    click.echo(f"Using IDAPython at: {python_path}")

    # Build Python API names from stubs
    click.echo("Scanning IDAPython stubs for API names...")
    py_api_names, module_apis = build_api_names_from_stubs(python_path)
    click.echo(f"Found {len(py_api_names)} Python API functions")

    # Merge Python API names into the known set
    combined_api_names = known_api_names | py_api_names

    # Collect Python API docs from stubs
    click.echo("Collecting Python API documentation from stubs...")
    py_api_docs = collect_python_api_docs(python_path, config)
    click.echo(f"Collected {len(py_api_docs)} Python API doc entries")

    # Merge Python docs: prefer Python stub docs (richer docstrings) over C++
    existing_names = {doc.name for doc in api_docs}
    for doc in py_api_docs:
        if doc.name not in existing_names:
            api_docs.append(doc)
        else:
            # Replace if the Python doc has a longer brief (richer docstring)
            for i, existing in enumerate(api_docs):
                if existing.name == doc.name and len(doc.brief) > len(existing.brief):
                    api_docs[i] = doc
                    break

    # Enumerate Python example scripts
    click.echo("Enumerating Python example scripts...")
    py_sources = enumerate_python_examples(python_path, config)
    click.echo(f"Found {len(py_sources)} Python example files")

    # Extract Python workflows
    click.echo("Extracting Python workflows...")
    py_workflow_count = 0
    for i, sf in enumerate(py_sources):
        workflows = extract_workflows_from_python(
            sf, combined_api_names, module_apis, config,
        )
        all_workflows.extend(workflows)
        py_workflow_count += len(workflows)
    click.echo(f"Extracted {py_workflow_count} Python workflows")
    click.echo(f"Total workflows (C++ + Python): {len(all_workflows)}")


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
