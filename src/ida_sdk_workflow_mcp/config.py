"""Configuration for the IDA SDK Workflow MCP server."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    sdk_path: Path | None = None
    version: str = ""  # e.g., "84" for IDA SDK 8.4
    db_base_path: Path = field(default_factory=lambda: Path("data/chroma_db"))
    max_files: int | None = None  # None = no limit
    search_results_default: int = 5

    @property
    def db_path(self) -> Path:
        """Versioned ChromaDB path: data/chroma_db/v84/."""
        if self.version:
            return self.db_base_path / f"v{self.version}"
        return self.db_base_path

    # Directories to scan within SDK source, ordered by trust/priority.
    # Each tuple: (subdirectory name, trust level string, category)
    scan_dirs: list[tuple[str, str, str]] = field(default_factory=lambda: [
        ("plugins", "highest", "plugin"),
        ("module", "high", "module"),
        ("ldr", "high", "loader"),
        ("dbg", "high", "debugger"),
    ])

    # Directories containing header files for API name extraction
    header_dirs: list[str] = field(default_factory=lambda: [
        "include",
    ])
