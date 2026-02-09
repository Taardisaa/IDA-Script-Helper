"""Tests for the version manager."""

import tempfile
from pathlib import Path

from ida_sdk_workflow_mcp.version_manager import (
    get_default_version,
    list_versions,
    validate_version,
)


def test_list_versions_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert list_versions(Path(tmpdir)) == []


def test_list_versions_nonexistent():
    assert list_versions(Path("/nonexistent/path")) == []


def test_list_versions_sorts_numerically():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        (base / "v84").mkdir()
        (base / "v80").mkdir()
        (base / "v90").mkdir()

        versions = list_versions(base)
        assert versions == ["80", "84", "90"]


def test_list_versions_ignores_non_version_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        (base / "v84").mkdir()
        (base / "other").mkdir()
        (base / "vfoo").mkdir()

        versions = list_versions(base)
        assert versions == ["84"]


def test_get_default_version():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        (base / "v80").mkdir()
        (base / "v84").mkdir()

        assert get_default_version(base) == "84"


def test_get_default_version_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert get_default_version(Path(tmpdir)) is None


def test_validate_version_exists():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        (base / "v84").mkdir()

        assert validate_version(base, "84") is True
        assert validate_version(base, "80") is False
