# IDA SDK Workflow MCP

An MCP server that helps LLMs write correct IDA Pro scripts by providing **API workflow retrieval** — not just individual function docs, but the correct **call sequences** extracted from real IDA SDK source code and IDAPython examples.

## The Problem

LLMs frequently get IDA SDK API call sequences wrong. Listing cross-references isn't a single API call — it requires calling `get_screen_ea()`, obtaining a `func_t*` with `get_func()`, iterating with `xrefblk_t::first_to()` / `xrefblk_t::next_to()`, and formatting output with `get_name()` and `msg()`. Miss any step and the script silently fails.

This tool automatically extracts these workflow patterns from IDA's own SDK examples (C++ plugins, processor modules, loaders) **and** IDAPython example scripts, indexes them, and serves them via MCP so any LLM can query them.

## Features

- **Dual-language support**: Extracts workflows from both C++ SDK examples and IDAPython scripts
- **SWIG stub parsing**: Harvests rich docstrings from `ida_*.py` stubs (`@param`, `@return`, signatures)
- **Data-flow tracking**: Follows variable assignments across API calls to show how outputs feed into inputs
- **Trust-ranked results**: Official SDK examples surface first, modules and loaders second
- **Semantic search**: Natural-language queries matched against workflow descriptions and API briefs
- **Multi-version support**: Index multiple SDK versions side-by-side, switch at query time

## MCP Tools

| Tool | Purpose | Input |
|------|---------|-------|
| `get_workflows` | Find API call sequences for a task | Natural-language task description |
| `get_api_doc` | Look up a function, struct, or class (fuzzy match) | Function/type name or keyword |
| `list_related_apis` | Find co-occurring APIs | Function or type name |
| `get_versions` | List all indexed SDK versions | — |
| `select_version` | Switch active SDK version | Version string (e.g., `"84"`) |

### Example

```
get_workflows("get the function at an address and print its name")
```

Returns:

```
=== Result 1 (trust: highest) ===
Workflow: run
Source: plugins/vcsample/vcsample.cpp

1. get_screen_ea(...)
2. get_func(...)        [uses ea from step 1]
3. get_func_name(...)   [uses pfn from step 2]
4. msg(...)

Source code:
  ea_t ea = get_screen_ea();
  func_t *pfn = get_func(ea);
  qstring name = get_func_name(ea);
  msg("Function: %s\n", name.c_str());
```

With `--python-path`, Python results appear alongside C++:

```
=== Result 2 (trust: highest) ===
Workflow: <module>
Source: python/examples/core/dump_flowchart.py

1. ida_kernwin.get_screen_ea(...)
2. ida_funcs.get_func(...)    [uses ea from step 1]
3. ida_gdl.FlowChart(...)     [uses func from step 2]
```

## Setup

```bash
# Clone and install
git clone https://github.com/ruotoy/IDA-Sdk-Workflow-MCP.git
cd IDA-Sdk-Workflow-MCP
python3.10 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

> **Note**: Python 3.10 is required — `tree-sitter-languages` does not ship wheels for 3.13+.

## Usage

### 1. Build the index

#### C++ only (IDA SDK)

```bash
ida-sdk-mcp-admin build-index \
  --sdk-path /path/to/idasdk_pro84 \
  --version 84
```

#### C++ + Python (IDA SDK + IDAPython)

```bash
ida-sdk-mcp-admin build-index \
  --sdk-path /path/to/idasdk_pro84 \
  --python-path /path/to/idapro-8.4/python \
  --version 84
```

The `--python-path` should point to the `python/` directory inside your IDA Pro installation. It expects:
- `3/ida_*.py` — SWIG-generated API stubs
- `3/idautils.py`, `3/idc.py` — higher-level utility modules
- `examples/` — official IDAPython example scripts

#### Options

| Option | Description |
|--------|-------------|
| `--sdk-path` | **(required)** Path to IDA SDK directory (e.g., `idasdk_pro84/`) |
| `--python-path` | Path to IDAPython directory (e.g., `idapro-8.4/python/`) |
| `--version` | **(required)** SDK version string (e.g., `84` for IDA 8.4) |
| `--db-path` | Base path for ChromaDB storage (default: `data/chroma_db`) |
| `--max-files` | Limit number of source files to process (for testing) |

### 2. Test queries

```bash
ida-sdk-mcp-admin inspect "decompile a function"
ida-sdk-mcp-admin inspect "cross references to an address"
ida-sdk-mcp-admin inspect "list all functions in a segment"
ida-sdk-mcp-admin inspect "enumerate file imports"
```

### 3. Add as MCP server

#### Claude Code

```bash
claude mcp add ida-sdk-workflow -- uv run --directory /path/to/IDA-Sdk-Workflow-MCP ida-sdk-mcp
```

Or create a `.mcp.json` file in the project root:

```json
{
  "mcpServers": {
    "ida-sdk-workflow": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/IDA-Sdk-Workflow-MCP", "ida-sdk-mcp"]
    }
  }
}
```

#### Claude Desktop

Add to `~/.config/Claude/claude_desktop_config.json` (Linux), `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "ida-sdk-workflow": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/IDA-Sdk-Workflow-MCP", "ida-sdk-mcp"]
    }
  }
}
```

#### After publishing to PyPI

```json
{
  "mcpServers": {
    "ida-sdk-workflow": {
      "command": "uvx",
      "args": ["ida-sdk-workflow-mcp"]
    }
  }
}
```

## How It Works

```
[1. Collect]  Enumerate source files from IDA SDK (C++) and IDAPython (Python)
      |         C++: plugins/, module/, ldr/, dbg/
      |         Python: python/examples/core/, hexrays/, analysis/, ...
      ↓
[2. Parse]    C++: tree-sitter C++ → AST
              Python: ast module → AST
              Stubs: ast module → API docs from ida_*.py SWIG docstrings
      ↓
[3. Extract]  Identify IDA API calls per function
              C++: idaman/ida_export patterns, member calls, qualified calls
              Python: module-qualified calls (ida_funcs.get_func),
                      direct imports (from ida_funcs import get_func)
              Track variable assignments to build data-flow edges
      ↓
[4. Index]    Store call chains + source snippets in ChromaDB
              Embed with semantic vectors for natural-language search
              Tag with language metadata (cpp / python)
      ↓
[5. Serve]    MCP server retrieves relevant workflows at query time
              Results ranked by trust level, then similarity
```

### Data sources by trust level

| Trust | C++ Sources | Python Sources |
|-------|-------------|----------------|
| Highest | `plugins/` — official SDK example plugins | `python/examples/` — official IDAPython examples |
| High | `module/`, `ldr/`, `dbg/` — processor modules, loaders, debuggers | — |
| Medium | `include/` — header declarations | — |

### Build statistics (SDK 8.4)

| Metric | C++ | Python | Combined |
|--------|-----|--------|----------|
| Source files | 356 | 89 examples | 445 |
| Extracted workflows | 921 | 112 | 1,033 |
| API calls captured | — | 505 | — |
| Data-flow edges | — | 143 | — |
| API doc entries | 1,443 (from headers) | 8,060 (from stubs) | 8,491 (merged) |

### Python extraction coverage

63 of 89 IDAPython example scripts (71%) produce at least one workflow. The remaining 26 break down as:

| Category | Count | Notes |
|----------|------:|-------|
| No IDA API calls at all | 10 | Hook skeletons, config files, pure boilerplate |
| Single API call (below min-2 threshold) | 8 | Trivial one-liners, no meaningful workflow |
| 2 calls spread across separate class methods | 6 | Each method has only 1 call; no single function reaches threshold |
| Non-standard import pattern | 2 | e.g., `from Choose import Choose` — not an `ida_*` module |

## Project Structure

```
src/ida_sdk_workflow_mcp/
├── server.py                       # MCP server (FastMCP, stdio transport)
├── cli.py                          # CLI: build-index, inspect, list-versions, serve
├── config.py                       # Configuration dataclass
├── version_manager.py              # Multi-version index management
├── collector/
│   ├── sdk_source.py               # Enumerate C++ files, build API names from headers
│   ├── python_source.py            # Enumerate Python examples, collect stub docs
│   └── doc_source.py               # Collect API docs from C++ headers
├── parser/
│   ├── cpp_parser.py               # tree-sitter C++ parsing
│   ├── python_parser.py            # ast-based Python parsing (imports, functions, metadata)
│   ├── html_parser.py              # Doxygen comment extraction from C++ headers
│   └── stub_parser.py              # SWIG stub parsing (ida_*.py → HeaderApiDoc)
├── extractor/
│   ├── models.py                   # Core data models (Workflow, ApiCall, DataFlowEdge, etc.)
│   ├── call_chain.py               # C++ workflow extraction (tree-sitter AST)
│   └── python_call_chain.py        # Python workflow extraction (ast module)
└── indexer/
    ├── store.py                    # ChromaDB ingestion (workflows + API docs)
    └── search.py                   # Semantic search interface
```

## Development

```bash
# Run tests (65 tests)
.venv/bin/pytest -v

# Lint
.venv/bin/ruff check src/ tests/
```

## License

MIT
