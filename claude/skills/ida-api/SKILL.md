---
name: ida-api
description: Look up IDA SDK API documentation, related APIs, or task workflows
user_invocable: true
auto_invoke:
  - look up IDA API
  - what does ida
  - IDA API for
  - how to use ida_
  - what is xrefblk_t
  - what is func_t
  - what is ea_t
---

# IDA API Lookup

Look up IDA SDK API documentation using the `ida-api-mcp` MCP tools. Operates in three modes depending on what the user asks for.

## Mode 1: Named API lookup

When the user asks about a specific function, struct, or class by name:

```
get_api_doc("<name>")
```

Examples:
- "what does `get_func` do?" → `get_api_doc("get_func")`
- "tell me about `xrefblk_t`" → `get_api_doc("xrefblk_t")`
- "what is `cfunc_t`?" → `get_api_doc("cfunc_t")`

Then call `list_related_apis` to show what's commonly used alongside it:

```
list_related_apis("<name>")
```

Present results as:
1. The API's signature, parameters, and return type
2. A brief description of what it does
3. Related APIs that are commonly used with it

## Mode 2: Related APIs

When the user asks "what APIs are related to X" or "what else do I need with X":

```
list_related_apis("<name>")
```

Then call `get_api_doc` on the top results to provide full details.

## Mode 3: Task-based search

When the user describes a task rather than naming a specific API:

```
get_workflows("<task description>")
```

Then call `get_api_doc` on each API in the returned workflow to provide full documentation.

Examples:
- "how do I iterate segments?" → `get_workflows("iterate over segments")`
- "how to get imports?" → `get_workflows("enumerate file imports")`

Present results as:
1. The recommended call sequence with data-flow dependencies
2. Brief docs for each API in the sequence
3. Source file where the pattern was found
