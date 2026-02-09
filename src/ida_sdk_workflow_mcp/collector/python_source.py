"""Collect and enumerate Python source files from an IDAPython installation.

Handles:
- Enumerating example scripts from python/examples/
- Validating an IDAPython directory layout
- Collecting API documentation from SWIG stub files
"""

from __future__ import annotations

import logging
from pathlib import Path

from ida_sdk_workflow_mcp.config import Config
from ida_sdk_workflow_mcp.extractor.models import HeaderApiDoc, SourceFile, TrustLevel
from ida_sdk_workflow_mcp.parser.stub_parser import parse_stub_file

logger = logging.getLogger(__name__)

# Map example subdirectory names to categories
_CATEGORY_MAP = {
    "core": "core",
    "hexrays": "hexrays",
    "analysis": "analysis",
    "debugging": "debugging",
    "idbhooks": "idbhooks",
    "idphooks": "idphooks",
    "uihooks": "uihooks",
    "widgets": "widgets",
    "pyqt": "pyqt",
    "cvt64": "cvt64",
    "idbs": "idbs",
}

# Modules to scan beyond ida_*.py
_EXTRA_STUBS = ("idautils.py", "idc.py")


def validate_python_dir(path: Path) -> bool:
    """Check that a path looks like an IDAPython installation directory.

    Expects at least the stubs directory ``3/`` with ``ida_funcs.py`` and
    an ``examples/`` directory.
    """
    stubs_dir = path / "3"
    examples_dir = path / "examples"
    return (
        stubs_dir.is_dir()
        and (stubs_dir / "ida_funcs.py").is_file()
        and examples_dir.is_dir()
    )


def enumerate_python_examples(
    python_dir: Path, config: Config,
) -> list[SourceFile]:
    """Walk python/examples/ subdirs, return SourceFile objects.

    All examples get HIGHEST trust (official Hex-Rays example scripts).
    """
    examples_dir = python_dir / "examples"
    if not examples_dir.is_dir():
        logger.warning("Examples directory not found: %s", examples_dir)
        return []

    results: list[SourceFile] = []

    for py_file in sorted(examples_dir.rglob("*.py")):
        # Determine category from parent directory name
        rel = py_file.relative_to(examples_dir)
        if len(rel.parts) > 1:
            category = _CATEGORY_MAP.get(rel.parts[0], rel.parts[0])
        else:
            category = "example"

        results.append(SourceFile(
            path=py_file,
            trust_level=TrustLevel.HIGHEST,
            category=category,
        ))

    if config.max_files is not None:
        results = results[:config.max_files]

    logger.info(
        "Found %d Python example files",
        len(results),
    )
    return results


def collect_python_api_docs(
    python_dir: Path, config: Config,
) -> list[HeaderApiDoc]:
    """Collect API documentation from all IDAPython SWIG stubs.

    Parses ida_*.py, idautils.py, and idc.py for function/class docs.
    """
    stubs_dir = python_dir / "3"
    if not stubs_dir.is_dir():
        logger.warning("Stubs directory not found: %s", stubs_dir)
        return []

    all_docs: list[HeaderApiDoc] = []

    # Parse all ida_*.py stubs
    for stub_path in sorted(stubs_dir.glob("ida_*.py")):
        docs = parse_stub_file(stub_path)
        all_docs.extend(docs)

    # Parse extra modules
    for extra in _EXTRA_STUBS:
        extra_path = stubs_dir / extra
        if extra_path.is_file():
            docs = parse_stub_file(extra_path)
            all_docs.extend(docs)

    logger.info("Collected %d Python API doc entries from stubs", len(all_docs))
    return all_docs
