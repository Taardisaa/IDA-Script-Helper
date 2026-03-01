"""Core data models for IDA SDK workflow extraction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class TrustLevel(Enum):
    HIGHEST = "highest"  # official SDK example plugins
    HIGH = "high"  # processor modules, loaders
    MEDIUM = "medium"  # include headers (declarations only)


@dataclass
class SourceFile:
    """A C++ source file to be processed."""

    path: Path
    trust_level: TrustLevel
    category: str  # "plugin", "module", "loader", "header"


@dataclass
class ApiCall:
    """A single IDA SDK API call."""

    class_name: str  # e.g., "func_t" for member calls, "" for free functions
    method_name: str  # e.g., "get_func", "openProgram", "<init>" for constructors
    full_text: str  # e.g., "get_func(ea)"
    line_number: int
    byte_offset: int  # position in source for ordering
    return_var: str | None = None  # variable name this result is assigned to
    receiver_var: str | None = None  # variable this is called on (None for free functions)
    argument_vars: list[str] = field(default_factory=list)


@dataclass
class DataFlowEdge:
    """Links one API call's output to another's input."""

    source_call_index: int  # index into Workflow.calls
    target_call_index: int  # index into Workflow.calls
    variable_name: str  # the variable connecting them
    role: str  # "receiver" or "argument"


@dataclass
class Workflow:
    """A complete API workflow extracted from a single function."""

    calls: list[ApiCall]
    data_flow: list[DataFlowEdge]
    source_snippet: str
    function_name: str
    file_path: str
    trust_level: TrustLevel
    category: str
    api_names_used: set[str] = field(default_factory=set)
    description: str = ""
    api_briefs: dict[str, str] = field(default_factory=dict)  # api_name -> brief description

    @property
    def id(self) -> str:
        """Unique identifier derived from source location and content."""
        call_sig = ",".join(f"{c.class_name}.{c.method_name}" for c in self.calls)
        key = f"{self.file_path}:{self.function_name}:{call_sig}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_display_text(self) -> str:
        """Format as the ordered step-by-step display shown to the user."""
        lines = [f"Workflow: {self.function_name}"]
        lines.append(f"Source: {self.file_path}")
        lines.append("")
        for i, call in enumerate(self.calls):
            if call.class_name:
                if call.method_name == "<init>":
                    step = f"{i + 1}. new {call.class_name}()"
                elif call.receiver_var:
                    step = f"{i + 1}. {call.receiver_var}.{call.method_name}(...)"
                else:
                    step = f"{i + 1}. {call.class_name}::{call.method_name}(...)"
            else:
                step = f"{i + 1}. {call.method_name}(...)"

            # Annotate with data flow info
            incoming = [e for e in self.data_flow if e.target_call_index == i]
            if incoming:
                deps = ", ".join(
                    f"uses {e.variable_name} from step {e.source_call_index + 1}"
                    for e in incoming
                )
                step += f"  [{deps}]"
            lines.append(step)
        return "\n".join(lines)

    def to_embedding_text(self) -> str:
        """Generate text used for semantic embedding/search."""
        parts = []
        if self.description:
            parts.append(f"IDA SDK workflow: {self.description}.")

        # Build step descriptions with API briefs when available
        steps = []
        for c in self.calls:
            name = f"{c.class_name}::{c.method_name}" if c.class_name else c.method_name
            brief = self.api_briefs.get(c.method_name, "")
            if brief:
                steps.append(f"{name} ({brief})")
            else:
                steps.append(name)
        parts.append(f"Steps: {' -> '.join(steps)}.")

        parts.append(f"Source function: {self.function_name}")
        return " ".join(parts)


@dataclass
class HeaderApiDoc:
    """API documentation extracted from a header file's Doxygen comments."""

    name: str  # function or type name
    brief: str  # one-line description
    signature: str  # full declaration
    header_file: str  # e.g., "funcs.hpp"
    kind: str  # "function", "struct", "class", "typedef", "enum"
    params: list[tuple[str, str]] = field(default_factory=list)  # (name, description)
    return_desc: str = ""
