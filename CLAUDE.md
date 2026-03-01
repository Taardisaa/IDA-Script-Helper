# IDA SDK Workflow MCP

This project provides an MCP server that indexes IDA Pro SDK call sequences and serves them to LLMs. It helps you write correct IDA scripts by providing real API workflow patterns extracted from official SDK examples.

## Behavioral Rules

**ALWAYS consult the `ida-api-mcp` MCP tools before writing any IDA-related code.** Do not rely on training data for IDA API usage — the SDK changes between versions and training data is frequently wrong. The MCP tools contain ground-truth workflows extracted from official SDK source code.

### Required workflow when writing IDA code

1. **`get_workflows`** — Search for the task you need to accomplish (e.g., "enumerate cross references to a function"). This returns proven call chains with data-flow dependencies.
2. **`get_api_doc`** — Look up any API function, struct, or class you're unsure about. Supports fuzzy matching.
3. **`list_related_apis`** — If the workflow seems incomplete or you need companion functions, find co-occurring APIs.
4. **`get_versions` / `select_version`** — Check and switch SDK versions if the user specifies a particular IDA version.

### Handling uninitialized index

The MCP tools require a built index to function. If any tool returns a message starting with **"NO INDEX INITIALIZED"**, do NOT treat this as an error or broken tool. Instead:

1. **Tell the user** the index needs to be built before IDA API queries will work.
2. **Ask the user** for the path to their IDA SDK directory (e.g., `/path/to/idasdk84`).
3. **Call `initialize_index()`** with their SDK path and version string (e.g., `"84"` for IDA 8.4).
4. Building the index takes a few minutes — inform the user it's in progress.

You can call **`get_versions()`** first as a quick health check to see if any versions are indexed.

### When to invoke these tools automatically

- User asks to "write an IDA script", "create an IDA plugin", or anything involving IDA Pro scripting
- User mentions IDA API functions (`get_func`, `xrefblk_t`, `decompile`, etc.)
- User asks "how do I do X in IDA"
- User asks about any `ida_*` module or function

## MCP Tool Reference

| Tool | Purpose | Input |
|------|---------|-------|
| `get_workflows` | Find API call sequences for a task | Natural-language task description |
| `get_api_doc` | Look up a function, struct, or class (fuzzy match) | Function/type name or keyword |
| `list_related_apis` | Find co-occurring APIs | Function or type name |
| `get_versions` | List all indexed SDK versions | — |
| `select_version` | Switch active SDK version | Version string (e.g., `"84"`) |

## IDA SDK Conventions

### IDAPython module naming

IDA Python APIs live in `ida_*` modules that mirror the C++ header names:

| Module | Header | Contents |
|--------|--------|----------|
| `ida_funcs` | `funcs.hpp` | Function management (`get_func`, `add_func`) |
| `ida_bytes` | `bytes.hpp` | Byte/data access (`get_byte`, `get_dword`) |
| `ida_hexrays` | `hexrays.hpp` | Decompiler (`decompile`, `cfunc_t`) |
| `ida_kernwin` | `kernwin.hpp` | UI interaction (`ask_addr`, `get_screen_ea`) |
| `ida_name` | `name.hpp` | Name management (`get_name`, `set_name`) |
| `ida_xref` | `xref.hpp` | Cross-references (`xrefblk_t`) |
| `ida_idaapi` | `ida.hpp` | Core types and constants |
| `ida_segment` | `segment.hpp` | Segment management |
| `ida_nalt` | `nalt.hpp` | Netnode alt values, imports |
| `ida_gdl` | `gdl.hpp` | Graph/flowchart support |
| `idautils` | — | High-level helpers (`Functions()`, `Segments()`) |
| `idc` | — | IDC compatibility layer |

### Key types

- `ea_t` — Address type (unsigned 32/64-bit depending on IDA bitness)
- `func_t` — Function descriptor (`.start_ea`, `.end_ea`, `.flags`)
- `xrefblk_t` — Cross-reference iterator (`.first_to()`, `.next_to()`, `.first_from()`, `.next_from()`)
- `qstring` — IDA string type (C++ only; Python uses regular `str`)
- `cfunc_t` / `cfuncptr_t` — Decompiled function (Hex-Rays)

### IDAPython script conventions

- Use explicit module imports: `import ida_funcs` not `from ida_funcs import *`
- Wrap logic in `def main():` with `if __name__ == "__main__": main()`
- Always check for `None` returns (`get_func()` returns `None` if no function at address)
- Use `print()` for output (not `ida_kernwin.msg()` in Python)
- Reference `examples/decompile_func_by_addr.py` for canonical style
