"""Extract IDA SDK API call chains from parsed Python ASTs.

Mirrors the C++ call_chain.py extractor but uses Python's ast module
to find IDA API calls in IDAPython example scripts.
"""

from __future__ import annotations

import ast
import logging
import re

from ida_sdk_workflow_mcp.config import Config
from ida_sdk_workflow_mcp.extractor.models import (
    ApiCall,
    DataFlowEdge,
    SourceFile,
    Workflow,
)
from ida_sdk_workflow_mcp.parser.python_parser import (
    extract_metadata,
    find_function_bodies,
    find_imports,
    parse_python,
)

logger = logging.getLogger(__name__)


_PREFIX_EXPANSIONS = {
    "get_": "Retrieve",
    "set_": "Set",
    "del_": "Delete",
    "delete_": "Delete",
    "add_": "Add",
    "is_": "Check if",
    "has_": "Check if has",
    "create_": "Create",
    "find_": "Find",
    "open_": "Open",
    "close_": "Close",
    "read_": "Read",
    "write_": "Write",
    "update_": "Update",
    "remove_": "Remove",
    "init_": "Initialize",
    "show_": "Show",
    "list_": "List",
    "enum_": "Enumerate",
}


def _generate_description(
    function_name: str,
    api_names: set[str],
    source_text: str,
    metadata: dict,
) -> str:
    """Auto-generate a workflow description from available context."""
    # Prefer metadata summary from the example script
    if metadata.get("summary"):
        return metadata["summary"]

    # Try docstring of the function
    try:
        tree = ast.parse(source_text)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == function_name:
                doc = ast.get_docstring(node)
                if doc:
                    return doc.split("\n")[0].strip()
    except SyntaxError:
        pass

    # Fall back: expand common prefixes
    base_name = function_name.split(".")[-1] if "." in function_name else function_name
    for prefix, verb in _PREFIX_EXPANSIONS.items():
        if base_name.startswith(prefix):
            rest = base_name[len(prefix):].replace("_", " ")
            return f"{verb} {rest}"

    # Last resort
    words = function_name.replace("_", " ").strip()
    api_list = ", ".join(sorted(api_names))
    return f"{words} using {api_list}"


def extract_workflows_from_python(
    source_file: SourceFile,
    known_api_names: set[str],
    module_apis: dict[str, set[str]],
    config: Config,
) -> list[Workflow]:
    """Extract all IDA API workflows from a single Python source file.

    Args:
        source_file: The Python source file to process.
        known_api_names: Flat set of known IDA API function names.
        module_apis: Mapping of module_name -> set of function names.
        config: Application configuration.

    Returns:
        List of Workflow objects, one per function that contains IDA API calls.
    """
    try:
        source = source_file.path.read_bytes()
        source_text = source.decode("utf-8", errors="replace")
    except (OSError, IOError) as e:
        logger.warning("Could not read %s: %s", source_file.path, e)
        return []

    try:
        tree = parse_python(source)
    except SyntaxError as e:
        logger.warning("Could not parse %s: %s", source_file.path, e)
        return []

    imports = find_imports(tree)
    metadata = extract_metadata(source_text)
    function_bodies = find_function_bodies(tree, source)

    # Build a reverse map: local_name -> module_name for IDA modules
    # e.g., {"ida_funcs": "ida_funcs", "f": "ida_funcs"} (if aliased)
    ida_module_map: dict[str, str] = {}
    for local_name, module_name in imports.items():
        if module_name in module_apis:
            ida_module_map[local_name] = module_name

    # Build direct name → True for "from ida_funcs import get_func"
    direct_imports: set[str] = set()
    for local_name, module_name in imports.items():
        if local_name in known_api_names and module_name in module_apis:
            direct_imports.add(local_name)

    workflows = []
    for func_name, func_node in function_bodies:
        workflow = _extract_workflow_from_function(
            function_name=func_name,
            func_node=func_node,
            source_text=source_text,
            known_api_names=known_api_names,
            module_apis=module_apis,
            ida_module_map=ida_module_map,
            direct_imports=direct_imports,
            source_file=source_file,
            metadata=metadata,
        )
        if workflow and len(workflow.calls) >= 2:
            workflows.append(workflow)

    return workflows


def _extract_workflow_from_function(
    function_name: str,
    func_node: ast.AST,
    source_text: str,
    known_api_names: set[str],
    module_apis: dict[str, set[str]],
    ida_module_map: dict[str, str],
    direct_imports: set[str],
    source_file: SourceFile,
    metadata: dict,
) -> Workflow | None:
    """Extract a workflow from a single function body."""
    # var_name -> (type_hint, call_index)  — call_index of -1 means pre-existing
    var_tracker: dict[str, tuple[str, int]] = {}

    calls: list[ApiCall] = []
    data_flow: list[DataFlowEdge] = []
    api_names_used: set[str] = set()

    # Walk all nodes in the function body in order
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue

        call = _process_call_node(
            node, known_api_names, module_apis, ida_module_map, direct_imports,
        )
        if call is None:
            continue

        call_index = len(calls)
        calls.append(call)
        api_names_used.add(call.method_name)
        if call.class_name:
            api_names_used.add(call.class_name)

    if not calls:
        return None

    # Track assignments and build data flow in a second pass
    _build_assignments_and_dataflow(
        func_node, calls, var_tracker, data_flow,
        known_api_names, module_apis, ida_module_map, direct_imports,
    )

    # Get source snippet
    source_lines = source_text.splitlines()
    if isinstance(func_node, ast.Module):
        # Pseudo-function: use all top-level lines
        snippet = source_text
    elif hasattr(func_node, "lineno") and hasattr(func_node, "end_lineno"):
        start = func_node.lineno - 1
        end = func_node.end_lineno if func_node.end_lineno else start + 1
        snippet = "\n".join(source_lines[start:end])
    else:
        snippet = source_text

    description = _generate_description(
        function_name, api_names_used, source_text, metadata,
    )

    return Workflow(
        calls=calls,
        data_flow=data_flow,
        source_snippet=snippet,
        function_name=function_name,
        file_path=str(source_file.path),
        trust_level=source_file.trust_level,
        category=source_file.category,
        api_names_used=api_names_used,
        description=description,
    )


def _process_call_node(
    node: ast.Call,
    known_api_names: set[str],
    module_apis: dict[str, set[str]],
    ida_module_map: dict[str, str],
    direct_imports: set[str],
) -> ApiCall | None:
    """Process an ast.Call node, return ApiCall if it's a known IDA API call."""
    func = node.func
    line = getattr(node, "lineno", 0)
    col = getattr(node, "col_offset", 0)

    # Extract argument variable names for data flow tracking
    arg_vars = _extract_arg_names(node)

    # Case 1: module.func() — e.g., ida_funcs.get_func(ea)
    if isinstance(func, ast.Attribute):
        # func.value is the object, func.attr is the method name
        if isinstance(func.value, ast.Name):
            obj_name = func.value.id
            method_name = func.attr

            # Check if obj_name is an imported IDA module
            if obj_name in ida_module_map:
                real_module = ida_module_map[obj_name]
                if real_module in module_apis and method_name in module_apis[real_module]:
                    return ApiCall(
                        class_name=obj_name,
                        method_name=method_name,
                        full_text=f"{obj_name}.{method_name}(...)",
                        line_number=line,
                        byte_offset=col,
                        receiver_var=None,
                        argument_vars=arg_vars,
                    )

            # Check if it's a method call on a tracked variable
            # (we don't have type info in Python, so check if method_name is known)
            if method_name in known_api_names:
                return ApiCall(
                    class_name=obj_name,
                    method_name=method_name,
                    full_text=f"{obj_name}.{method_name}(...)",
                    line_number=line,
                    byte_offset=col,
                    receiver_var=obj_name,
                    argument_vars=arg_vars,
                )

    # Case 2: func() — direct call, e.g., get_func(ea) after "from ida_funcs import get_func"
    elif isinstance(func, ast.Name):
        func_name = func.id
        if func_name in direct_imports or func_name in known_api_names:
            return ApiCall(
                class_name="",
                method_name=func_name,
                full_text=f"{func_name}(...)",
                line_number=line,
                byte_offset=col,
                receiver_var=None,
                argument_vars=arg_vars,
            )

    return None


def _extract_arg_names(node: ast.Call) -> list[str]:
    """Extract simple name identifiers from call arguments."""
    names = []
    for arg in node.args:
        if isinstance(arg, ast.Name):
            names.append(arg.id)
        elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
            names.append(f"{arg.value.id}.{arg.attr}")
    return names


def _build_assignments_and_dataflow(
    func_node: ast.AST,
    calls: list[ApiCall],
    var_tracker: dict[str, tuple[str, int]],
    data_flow: list[DataFlowEdge],
    known_api_names: set[str],
    module_apis: dict[str, set[str]],
    ida_module_map: dict[str, str],
    direct_imports: set[str],
) -> None:
    """Second pass: track variable assignments and build data flow edges."""
    # Build a map from (lineno, col_offset) -> call_index for quick lookup
    call_positions: dict[tuple[int, int], int] = {}
    for i, call in enumerate(calls):
        call_positions[(call.line_number, call.byte_offset)] = i

    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            # e.g., func = ida_funcs.get_func(ea)
            if (
                len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
            ):
                var_name = node.targets[0].id
                call_line = getattr(node.value, "lineno", 0)
                call_col = getattr(node.value, "col_offset", 0)
                call_idx = call_positions.get((call_line, call_col))
                if call_idx is not None:
                    calls[call_idx].return_var = var_name
                    var_tracker[var_name] = (calls[call_idx].method_name, call_idx)

    # Now build data flow edges
    for i, call in enumerate(calls):
        # Check receiver
        if call.receiver_var and call.receiver_var in var_tracker:
            _type, source_idx = var_tracker[call.receiver_var]
            if source_idx != i and source_idx >= 0:
                data_flow.append(DataFlowEdge(
                    source_call_index=source_idx,
                    target_call_index=i,
                    variable_name=call.receiver_var,
                    role="receiver",
                ))

        # Check arguments
        for arg_var in call.argument_vars:
            # Handle dotted names like "func.start_ea" — use the base variable
            base_var = arg_var.split(".")[0]
            if base_var in var_tracker:
                _type, source_idx = var_tracker[base_var]
                if source_idx != i and source_idx >= 0:
                    data_flow.append(DataFlowEdge(
                        source_call_index=source_idx,
                        target_call_index=i,
                        variable_name=arg_var,
                        role="argument",
                    ))
