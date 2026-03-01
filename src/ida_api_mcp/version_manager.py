"""Manage indexed SDK versions stored in data/chroma_db/v*/."""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_VERSION_DIR_RE = re.compile(r"^v(\d+)$")


def list_versions(db_base_path: Path) -> list[str]:
    """List all indexed SDK versions, sorted numerically ascending.

    Returns version strings like ["80", "84"].
    """
    if not db_base_path.is_dir():
        return []

    versions = []
    for child in db_base_path.iterdir():
        if child.is_dir():
            m = _VERSION_DIR_RE.match(child.name)
            if m:
                versions.append(m.group(1))

    versions.sort(key=int)
    return versions


def get_default_version(db_base_path: Path) -> str | None:
    """Get the highest indexed version (default for tool calls).

    Returns the version string (e.g., "84") or None if no versions exist.
    """
    versions = list_versions(db_base_path)
    return versions[-1] if versions else None


def validate_version(db_base_path: Path, version: str) -> bool:
    """Check if a specific version has been indexed."""
    version_dir = db_base_path / f"v{version}"
    return version_dir.is_dir()
