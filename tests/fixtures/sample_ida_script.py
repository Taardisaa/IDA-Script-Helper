"""
summary: list all functions and their basic blocks

description:
  Enumerate all functions in the current IDB, printing their
  names and the number of basic blocks in each function's flowchart.

keywords: functions, flowchart, basic blocks
"""

import ida_funcs
import ida_gdl
import ida_kernwin

ea = ida_kernwin.get_screen_ea()
func = ida_funcs.get_func(ea)
if func:
    name = ida_funcs.get_func_name(ea)
    print("Current function: %s" % name)

    fc = ida_gdl.FlowChart(func)
    print("Number of basic blocks: %d" % fc.size)

    for block in fc:
        print("  Block %d: %x - %x" % (block.id, block.start_ea, block.end_ea))
else:
    print("No function at current address")

# Also list all functions
qty = ida_funcs.get_func_qty()
print("Total functions: %d" % qty)
