"""Collect API documentation from IDA SDK header files.

Parses Doxygen-style comments from .hpp files in include/ to build
API documentation entries. These are later merged with workflow usage
counts during indexing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ida_api_mcp.config import Config
from ida_api_mcp.extractor.models import HeaderApiDoc
from ida_api_mcp.parser.html_parser import parse_header_file

logger = logging.getLogger(__name__)


def collect_api_docs(sdk_root: Path, config: Config) -> list[HeaderApiDoc]:
    """Collect all API documentation from SDK header files."""
    all_docs: list[HeaderApiDoc] = []

    for header_dir in config.header_dirs:
        include_path = sdk_root / header_dir
        if not include_path.is_dir():
            continue

        for hpp_file in sorted(include_path.rglob("*.hpp")):
            docs = parse_header_file(hpp_file)
            all_docs.extend(docs)

    logger.info("Collected %d API doc entries from headers", len(all_docs))
    return all_docs
