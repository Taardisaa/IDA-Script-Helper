"""
Decompile a function by address.

Prompts the user for an address, locates the function containing it,
and prints the decompiled pseudocode.

Usage: Run in IDA Pro via File -> Script file...
"""

import ida_funcs
import ida_hexrays
import ida_kernwin


def main():
    ea = ida_kernwin.ask_addr(0, "Enter function address:")
    if ea is None:
        return

    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        print("No function found at 0x%X" % ea)
        return

    print("Function: 0x%X - 0x%X" % (pfn.start_ea, pfn.end_ea))

    cf = ida_hexrays.decompile(pfn.start_ea)
    if cf is None:
        print("Decompilation failed at 0x%X" % pfn.start_ea)
        return

    print(str(cf))


if __name__ == "__main__":
    main()
