"""Shared pipeline for building the IDA SDK workflow index."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ida_api_mcp.collector.doc_source import collect_api_docs
from ida_api_mcp.collector.sdk_source import (
    build_known_api_names,
    enumerate_cpp_files,
    validate_sdk_root,
)
from ida_api_mcp.config import Config
from ida_api_mcp.extractor.call_chain import extract_workflows_from_source
from ida_api_mcp.indexer.store import (
    build_api_docs_index,
    build_workflow_index,
    get_client,
)


def build_index_pipeline(
    sdk_path: Path,
    version: str,
    python_path: Path | None = None,
    db_base_path: Path = Path("data/chroma_db"),
    max_files: int | None = None,
    progress: Callable[[str], None] = lambda _: None,
) -> None:
    """Run the full IDA SDK index-build pipeline."""
    if not validate_sdk_root(sdk_path):
        raise ValueError(f"{sdk_path} does not look like an IDA SDK tree.")

    config = Config(
        sdk_path=sdk_path,
        python_path=python_path,
        version=version,
        db_base_path=db_base_path,
        max_files=max_files,
    )

    progress(f"Using IDA SDK at: {sdk_path}")
    progress(f"Version: v{version}")

    progress("Scanning headers for known API names...")
    known_api_names = build_known_api_names(sdk_path, config)
    progress(f"Found {len(known_api_names)} known C++ API functions")

    progress("Enumerating C++ source files...")
    source_files = enumerate_cpp_files(sdk_path, config)
    progress(f"Found {len(source_files)} C++ files to process")

    progress("Extracting C++ workflows...")
    all_workflows = []
    for i, source_file in enumerate(source_files):
        if (i + 1) % 100 == 0:
            progress(f"  Processed {i + 1}/{len(source_files)} files...")
        workflows = extract_workflows_from_source(source_file, known_api_names, config)
        all_workflows.extend(workflows)
    progress(f"Extracted {len(all_workflows)} C++ workflows")

    progress("Collecting API documentation from headers...")
    api_docs = collect_api_docs(sdk_path, config)
    progress(f"Collected {len(api_docs)} C++ API doc entries")

    if python_path:
        _run_python_pipeline(
            python_path=python_path,
            config=config,
            known_api_names=known_api_names,
            all_workflows=all_workflows,
            api_docs=api_docs,
            progress=progress,
        )

    progress("Building ChromaDB index...")
    client = get_client(config.db_path)
    api_briefs = {doc.name: doc.brief for doc in api_docs if doc.brief}
    build_workflow_index(
        client,
        all_workflows,
        api_briefs=api_briefs,
        sdk_version=version,
    )
    build_api_docs_index(client, all_workflows, api_docs)
    progress(f"Index built at: {config.db_path}")
    progress("Done!")


def _run_python_pipeline(
    python_path: Path,
    config: Config,
    known_api_names: set[str],
    all_workflows: list,
    api_docs: list,
    progress: Callable[[str], None],
) -> None:
    """Run the IDAPython collection/extraction pipeline."""
    from ida_api_mcp.collector.python_source import (
        collect_python_api_docs,
        enumerate_python_examples,
        validate_python_dir,
    )
    from ida_api_mcp.extractor.python_call_chain import (
        extract_workflows_from_python,
    )
    from ida_api_mcp.parser.stub_parser import build_api_names_from_stubs

    if not validate_python_dir(python_path):
        progress(
            f"Warning: {python_path} does not look like an IDAPython directory, skipping."
        )
        return

    progress(f"Using IDAPython at: {python_path}")

    progress("Scanning IDAPython stubs for API names...")
    py_api_names, module_apis = build_api_names_from_stubs(python_path)
    progress(f"Found {len(py_api_names)} Python API functions")
    combined_api_names = known_api_names | py_api_names

    progress("Collecting Python API documentation from stubs...")
    py_api_docs = collect_python_api_docs(python_path, config)
    progress(f"Collected {len(py_api_docs)} Python API doc entries")

    existing_names = {doc.name for doc in api_docs}
    for doc in py_api_docs:
        if doc.name not in existing_names:
            api_docs.append(doc)
        else:
            for i, existing in enumerate(api_docs):
                if existing.name == doc.name and len(doc.brief) > len(existing.brief):
                    api_docs[i] = doc
                    break

    progress("Enumerating Python example scripts...")
    py_sources = enumerate_python_examples(python_path, config)
    progress(f"Found {len(py_sources)} Python example files")

    progress("Extracting Python workflows...")
    py_workflow_count = 0
    for source_file in py_sources:
        workflows = extract_workflows_from_python(
            source_file,
            combined_api_names,
            module_apis,
            config,
        )
        all_workflows.extend(workflows)
        py_workflow_count += len(workflows)

    progress(f"Extracted {py_workflow_count} Python workflows")
    progress(f"Total workflows (C++ + Python): {len(all_workflows)}")
