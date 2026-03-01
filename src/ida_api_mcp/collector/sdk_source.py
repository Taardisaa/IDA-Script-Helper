"""Collect and enumerate C++ source files from an IDA SDK tree."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ida_api_mcp.config import Config
from ida_api_mcp.extractor.models import SourceFile, TrustLevel

logger = logging.getLogger(__name__)

TRUST_MAP = {
    "highest": TrustLevel.HIGHEST,
    "high": TrustLevel.HIGH,
    "medium": TrustLevel.MEDIUM,
}

# Regex to find exported API functions in headers: idaman <type> ida_export <name>(
_IDAMAN_RE = re.compile(r"ida_export\s+(\w+)\s*\(")


def validate_sdk_root(path: Path) -> bool:
    """Check that a path looks like an IDA SDK tree."""
    return (path / "include").is_dir() and (path / "plugins").is_dir()


def enumerate_cpp_files(sdk_root: Path, config: Config) -> list[SourceFile]:
    """Walk IDA SDK tree, return C++ files ranked by trust.

    Files are deduplicated: if a file matches a higher-trust pattern,
    it won't be included again under a lower-trust pattern.
    """
    if not validate_sdk_root(sdk_root):
        raise ValueError(
            f"{sdk_root} does not look like an IDA SDK tree "
            "(expected include/ and plugins/ directories)"
        )

    seen_paths: set[Path] = set()
    results: list[SourceFile] = []

    for subdir, trust_str, category in config.scan_dirs:
        trust = TRUST_MAP[trust_str]
        scan_path = sdk_root / subdir
        if not scan_path.is_dir():
            continue

        # Collect .cpp and .h files (IDA SDK uses .cpp for source)
        for ext in ("*.cpp", "*.c"):
            for path in sorted(scan_path.rglob(ext)):
                resolved = path.resolve()
                if resolved in seen_paths:
                    continue
                seen_paths.add(resolved)
                results.append(SourceFile(path=path, trust_level=trust, category=category))

    if config.max_files is not None:
        results = results[:config.max_files]

    logger.info(
        "Found %d C++ files (%d highest, %d high, %d medium trust)",
        len(results),
        sum(1 for f in results if f.trust_level == TrustLevel.HIGHEST),
        sum(1 for f in results if f.trust_level == TrustLevel.HIGH),
        sum(1 for f in results if f.trust_level == TrustLevel.MEDIUM),
    )
    return results


def build_known_api_names(sdk_root: Path, config: Config) -> set[str]:
    """Build a set of known IDA SDK API function names from headers.

    Scans header files for the `idaman ... ida_export func_name(` pattern
    to identify all exported SDK functions.
    """
    api_names: set[str] = set()

    for header_dir in config.header_dirs:
        include_path = sdk_root / header_dir
        if not include_path.is_dir():
            continue

        for hpp_file in include_path.rglob("*.hpp"):
            try:
                content = hpp_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in _IDAMAN_RE.finditer(content):
                api_names.add(m.group(1))

    logger.info("Built known API name set: %d functions", len(api_names))
    return api_names
