"""Extract IDA SDK API call chains from parsed C++ ASTs."""

from __future__ import annotations

import logging
import re
from tree_sitter import Node

from ida_sdk_workflow_mcp.config import Config
from ida_sdk_workflow_mcp.extractor.models import (
    ApiCall,
    DataFlowEdge,
    SourceFile,
    Workflow,
)
from ida_sdk_workflow_mcp.parser.cpp_parser import (
    find_function_bodies,
    find_includes,
    get_node_text,
    parse_cpp,
)

logger = logging.getLogger(__name__)


def _walk_nodes_by_offset(node: Node) -> list[Node]:
    """Recursively collect all descendant nodes, sorted by byte offset."""
    nodes = []
    cursor = node.walk()

    def _visit():
        nodes.append(cursor.node)
        if cursor.goto_first_child():
            _visit()
            while cursor.goto_next_sibling():
                _visit()
            cursor.goto_parent()

    _visit()
    nodes.sort(key=lambda n: n.start_byte)
    return nodes


def _extract_argument_identifiers(args_node: Node, source: bytes) -> list[str]:
    """Extract identifier names from an argument list node."""
    identifiers = []
    for child in args_node.named_children:
        if child.type == "identifier":
            identifiers.append(get_node_text(child, source))
        elif child.type == "field_expression":
            # e.g., xb.from — use full text
            identifiers.append(get_node_text(child, source))
        elif child.type == "pointer_expression":
            # e.g., &func_name — extract the operand
            for sub in child.named_children:
                if sub.type == "identifier":
                    identifiers.append(get_node_text(sub, source))
    return identifiers


def _generate_description(
    function_name: str, api_names: set[str], source_snippet: str
) -> str:
    """Auto-generate a workflow description from available context."""
    # Extract C-style comment or /// comments above the method if present
    comment_match = re.search(
        r'/\*\*(.*?)\*/', source_snippet, re.DOTALL
    )
    if comment_match:
        comment = comment_match.group(1)
        comment = re.sub(r'\s*\*\s*', ' ', comment).strip()
        comment = re.sub(r'@\w+.*', '', comment).strip()
        if comment:
            return comment

    # Try /// style comments
    doc_lines = []
    for line in source_snippet.splitlines():
        stripped = line.strip()
        if stripped.startswith("///"):
            doc_lines.append(re.sub(r"^///\s*", "", stripped))
        elif doc_lines:
            break
    if doc_lines:
        return " ".join(doc_lines).strip()

    # Fall back to function name + API names
    # Convert snake_case and CamelCase to words
    words = function_name.replace("::", " ").replace("_", " ").strip()
    api_list = ", ".join(sorted(api_names))
    return f"{words} using {api_list}"


def extract_workflows_from_source(
    source_file: SourceFile,
    known_api_names: set[str],
    config: Config,
) -> list[Workflow]:
    """Extract all IDA SDK API workflows from a single C++ source file.

    Args:
        source_file: The source file to process.
        known_api_names: Set of known IDA API function names (from headers).
        config: Application configuration.

    Returns:
        List of Workflow objects, one per function that contains IDA API calls.
    """
    try:
        source = source_file.path.read_bytes()
    except (OSError, IOError) as e:
        logger.warning("Could not read %s: %s", source_file.path, e)
        return []

    tree = parse_cpp(source)
    includes = find_includes(tree, source)

    # Check if this file includes IDA headers (quick filter)
    ida_includes = {inc for inc in includes if inc.endswith(".hpp")}
    if not ida_includes:
        return []

    function_bodies = find_function_bodies(tree, source)
    workflows = []

    for func_name, body_node in function_bodies:
        workflow = _extract_workflow_from_function(
            function_name=func_name,
            body_node=body_node,
            source=source,
            known_api_names=known_api_names,
            source_file=source_file,
        )
        if workflow and len(workflow.calls) >= 2:
            workflows.append(workflow)

    return workflows


def _extract_workflow_from_function(
    function_name: str,
    body_node: Node,
    source: bytes,
    known_api_names: set[str],
    source_file: SourceFile,
) -> Workflow | None:
    """Extract a workflow from a single function body."""
    # Track variables assigned from API calls
    # var_name -> (type_name, call_index)
    # call_index of -1 means pre-existing (parameter, not from a call)
    var_tracker: dict[str, tuple[str, int]] = {}

    # Seed var_tracker with function parameters
    func_node = body_node.parent
    if func_node is not None:
        _seed_parameters(func_node, source, var_tracker)

    calls: list[ApiCall] = []
    data_flow: list[DataFlowEdge] = []
    api_names_used: set[str] = set()

    all_nodes = _walk_nodes_by_offset(body_node)

    for node in all_nodes:
        call = None

        if node.type == "call_expression":
            call = _process_call_expression(
                node, source, known_api_names, var_tracker,
            )

        if call is None:
            continue

        call_index = len(calls)
        calls.append(call)
        api_names_used.add(call.method_name)
        if call.class_name:
            api_names_used.add(call.class_name)

        # Track variable assignment
        _track_variable_assignment(
            node, source, call, call_index, var_tracker,
        )

        # Build data flow edges
        _build_data_flow_edges(call, call_index, var_tracker, data_flow)

    if not calls:
        return None

    # Get the full function source snippet
    snippet_start = func_node.start_byte if func_node else body_node.start_byte
    snippet_end = body_node.end_byte
    source_snippet = source[snippet_start:snippet_end].decode("utf-8", errors="replace")

    description = _generate_description(function_name, api_names_used, source_snippet)

    return Workflow(
        calls=calls,
        data_flow=data_flow,
        source_snippet=source_snippet,
        function_name=function_name,
        file_path=str(source_file.path),
        trust_level=source_file.trust_level,
        category=source_file.category,
        api_names_used=api_names_used,
        description=description,
    )


def _seed_parameters(func_node: Node, source: bytes, var_tracker: dict) -> None:
    """Seed var_tracker with function parameter types."""
    # In C++ tree-sitter, function_definition -> declarator -> parameter_list
    declarator = func_node.child_by_field_name("declarator")
    if declarator is None:
        return

    # Navigate through possible wrapper nodes to find parameter_list
    node = declarator
    while node and node.type in ("pointer_declarator", "reference_declarator"):
        for child in node.children:
            if child.type == "function_declarator":
                node = child
                break
        else:
            return

    if node.type != "function_declarator":
        return

    params = node.child_by_field_name("parameters")
    if params is None:
        return

    for param in params.named_children:
        if param.type == "parameter_declaration":
            type_node = param.child_by_field_name("type")
            decl_node = param.child_by_field_name("declarator")
            if type_node and decl_node:
                type_name = get_node_text(type_node, source)
                # Handle pointer/reference declarators: ea_t -> ea_t, func_t* -> func_t
                param_name = get_node_text(decl_node, source).lstrip("*&")
                var_tracker[param_name] = (type_name, -1)


def _process_call_expression(
    node: Node,
    source: bytes,
    known_api_names: set[str],
    var_tracker: dict[str, tuple[str, int]],
) -> ApiCall | None:
    """Process a call expression node.

    Handles:
    - Free function calls: get_func(ea)
    - Member calls: xb.first_to(target, XREF_ALL)
    - Qualified calls: Type::method()
    """
    func_node = node.child_by_field_name("function")
    args_node = node.child_by_field_name("arguments")
    if func_node is None:
        return None

    arg_vars = _extract_argument_identifiers(args_node, source) if args_node else []

    # Case 1: Simple identifier — free function call like get_func(ea)
    if func_node.type == "identifier":
        func_name = get_node_text(func_node, source)
        if func_name in known_api_names:
            return ApiCall(
                class_name="",
                method_name=func_name,
                full_text=get_node_text(node, source),
                line_number=node.start_point[0] + 1,
                byte_offset=node.start_byte,
                receiver_var=None,
                argument_vars=arg_vars,
            )

    # Case 2: Field expression — member call like xb.first_to(...)
    elif func_node.type == "field_expression":
        object_node = func_node.child_by_field_name("argument")
        field_node = func_node.child_by_field_name("field")
        if object_node is not None and field_node is not None:
            receiver = get_node_text(object_node, source)
            method = get_node_text(field_node, source)

            # Check if the receiver is a tracked variable
            if receiver in var_tracker:
                class_name = var_tracker[receiver][0]
                return ApiCall(
                    class_name=class_name,
                    method_name=method,
                    full_text=get_node_text(node, source),
                    line_number=node.start_point[0] + 1,
                    byte_offset=node.start_byte,
                    receiver_var=receiver,
                    argument_vars=arg_vars,
                )

            # Check if the method name itself is a known API
            if method in known_api_names:
                return ApiCall(
                    class_name=receiver,
                    method_name=method,
                    full_text=get_node_text(node, source),
                    line_number=node.start_point[0] + 1,
                    byte_offset=node.start_byte,
                    receiver_var=receiver,
                    argument_vars=arg_vars,
                )

    # Case 3: Qualified identifier — Type::method() like msg() or static calls
    elif func_node.type == "qualified_identifier":
        scope_node = func_node.child_by_field_name("scope")
        name_node = func_node.child_by_field_name("name")
        if scope_node and name_node:
            scope = get_node_text(scope_node, source)
            name = get_node_text(name_node, source)
            if name in known_api_names:
                return ApiCall(
                    class_name=scope,
                    method_name=name,
                    full_text=get_node_text(node, source),
                    line_number=node.start_point[0] + 1,
                    byte_offset=node.start_byte,
                    receiver_var=None,
                    argument_vars=arg_vars,
                )

    # Case 4: Template function call — template_function<type>(args)
    elif func_node.type == "template_function":
        name_node = func_node.child_by_field_name("name")
        if name_node is not None:
            func_name = get_node_text(name_node, source)
            if func_name in known_api_names:
                return ApiCall(
                    class_name="",
                    method_name=func_name,
                    full_text=get_node_text(node, source),
                    line_number=node.start_point[0] + 1,
                    byte_offset=node.start_byte,
                    receiver_var=None,
                    argument_vars=arg_vars,
                )

    return None


def _track_variable_assignment(
    node: Node,
    source: bytes,
    call: ApiCall,
    call_index: int,
    var_tracker: dict[str, tuple[str, int]],
) -> None:
    """Check if this call's result is assigned to a variable and track it."""
    parent = node.parent
    if parent is None:
        return

    # Case: init_declarator -> declaration
    #   e.g., func_t *pfn = get_func(ea);
    if parent.type == "init_declarator":
        value_node = parent.child_by_field_name("value")
        decl_node = parent.child_by_field_name("declarator")
        if value_node == node and decl_node is not None:
            var_name = get_node_text(decl_node, source).lstrip("*&")
            call.return_var = var_name

            # Try to get the declared type from the parent declaration
            grandparent = parent.parent
            if grandparent and grandparent.type == "declaration":
                type_node = grandparent.child_by_field_name("type")
                if type_node:
                    type_name = get_node_text(type_node, source)
                    var_tracker[var_name] = (type_name, call_index)
                    return

            # Fall back to the call's class name
            tracked_type = call.class_name if call.class_name else call.method_name
            var_tracker[var_name] = (tracked_type, call_index)

    # Case: assignment_expression
    #   e.g., pfn = get_func(ea);
    elif parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        right = parent.child_by_field_name("right")
        if right == node and left is not None and left.type == "identifier":
            var_name = get_node_text(left, source)
            call.return_var = var_name
            tracked_type = call.class_name if call.class_name else call.method_name
            var_tracker[var_name] = (tracked_type, call_index)


def _build_data_flow_edges(
    call: ApiCall,
    call_index: int,
    var_tracker: dict[str, tuple[str, int]],
    data_flow: list[DataFlowEdge],
) -> None:
    """Build data flow edges from tracked variables into this call."""
    # Check receiver
    if call.receiver_var and call.receiver_var in var_tracker:
        _source_class, source_idx = var_tracker[call.receiver_var]
        if source_idx != call_index and source_idx >= 0:
            data_flow.append(DataFlowEdge(
                source_call_index=source_idx,
                target_call_index=call_index,
                variable_name=call.receiver_var,
                role="receiver",
            ))

    # Check arguments
    for arg_var in call.argument_vars:
        if arg_var in var_tracker:
            _source_class, source_idx = var_tracker[arg_var]
            if source_idx != call_index and source_idx >= 0:
                data_flow.append(DataFlowEdge(
                    source_call_index=source_idx,
                    target_call_index=call_index,
                    variable_name=arg_var,
                    role="argument",
                ))
