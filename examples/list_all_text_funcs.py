"""
List all functions in the .text segment.

Finds the .text segment by name, enumerates every function within it,
and prints each function's name and address range.

Usage: Run in IDA Pro via File -> Script file...
"""

import ida_funcs
import ida_segment
import idautils


def main():
    seg = ida_segment.get_segm_by_name(".text")
    if seg is None:
        print("Could not find .text segment")
        return

    print("Functions in .text (0x%X - 0x%X):" % (seg.start_ea, seg.end_ea))

    count = 0
    for func_ea in idautils.Functions(seg.start_ea, seg.end_ea):
        name = ida_funcs.get_func_name(func_ea)
        pfn = ida_funcs.get_func(func_ea)
        if pfn is not None:
            print("  0x%X - 0x%X  %s" % (pfn.start_ea, pfn.end_ea, name))
        else:
            print("  0x%X  %s" % (func_ea, name))
        count += 1

    print("\nTotal: %d functions" % count)


if __name__ == "__main__":
    main()
