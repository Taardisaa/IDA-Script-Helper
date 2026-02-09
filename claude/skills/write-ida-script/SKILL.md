---
name: write-ida-script
description: Write an IDAPython script using verified API workflows from the IDA SDK MCP server
user_invocable: true
auto_invoke:
  - write an IDA script
  - write an IDAPython script
  - create an IDA plugin
  - create an IDA script
  - IDA script that
  - IDAPython script
---

# Write IDA Script

Write an IDAPython script by first consulting the `ida-sdk-workflow` MCP tools to retrieve verified API call sequences, then composing the script from those patterns.

## Process

Follow these steps in order:

### 1. Decompose the request

Break the user's request into discrete sub-tasks. For example, "list all functions and their cross-references" becomes:
- Sub-task A: enumerate all functions
- Sub-task B: get cross-references for each function

### 2. Retrieve workflows

For each sub-task, call `get_workflows` with a natural-language description:

```
get_workflows("enumerate all functions in the database")
get_workflows("get cross references to a function")
```

### 3. Look up unfamiliar APIs

For any API function in the workflow results that you're not confident about, call `get_api_doc`:

```
get_api_doc("xrefblk_t")
get_api_doc("get_func_name")
```

### 4. Find companion APIs if needed

If a workflow seems incomplete (e.g., you have iteration but no formatting), call `list_related_apis`:

```
list_related_apis("get_func")
```

### 5. Write the script

Compose the script following these conventions:

- **Explicit imports**: `import ida_funcs`, not `from ida_funcs import *`
- **`main()` wrapper**: All logic inside `def main():` with `if __name__ == "__main__": main()`
- **None checks**: Always check return values — `get_func()`, `decompile()`, etc. can return `None`
- **`print()` for output**: Use `print()` in IDAPython, not `ida_kernwin.msg()`
- **Module-qualified calls**: `ida_funcs.get_func(ea)`, not bare `get_func(ea)`

Use `examples/decompile_func_by_addr.py` as the canonical style reference.

### 6. Explain the script

After writing the script, briefly explain:
- Which workflows/API patterns were used
- What each major section does
- Any limitations or assumptions

## Example

User: "write an IDAPython script that lists all functions with their sizes"

1. Sub-tasks: enumerate functions, compute size, format output
2. `get_workflows("enumerate all functions")` → reveals `idautils.Functions()` + `ida_funcs.get_func()`
3. `get_api_doc("get_func")` → confirms `func_t` has `.start_ea` and `.end_ea`
4. Write script using `idautils.Functions()` iterator, `ida_funcs.get_func()` for each, size = `end_ea - start_ea`
