"""
Print microcode of a basic block by its head address.

Prompts for an address, generates microcode for the containing function,
finds the block that includes that address, and prints its micro-instructions.

Usage: Run in IDA Pro via File -> Script file...
       Requires Hex-Rays decompiler.
"""

import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_range


def print_block_microcode(ea, maturity=ida_hexrays.MMAT_GLBOPT1):
    """Print the microcode block containing `ea`.

    Args:
        ea: Address inside the target block.
        maturity: Microcode maturity level (default MMAT_GLBOPT1).
    """
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays is not available")
        return

    pfn = ida_funcs.get_func(ea)
    if pfn is None:
        print("No function at 0x%X" % ea)
        return

    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t()
    mbr.ranges.push_back(ida_range.range_t(pfn.start_ea, pfn.end_ea))
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_WARNINGS, maturity
    )
    if mba is None:
        print("Failed to generate microcode: 0x%X: %s" % (hf.errea, hf.str))
        return

    found = None
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk.start <= ea < blk.end:
            found = blk
            break

    if found is None:
        print("No block contains 0x%X. Available blocks:" % ea)
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            print("  Block %d: 0x%X - 0x%X" % (i, blk.start, blk.end))
        return

    vp = ida_hexrays.vd_printer_t()
    found._print(vp)


def main():
    ea = ida_kernwin.ask_addr(0, "Enter block head address:")
    if ea is None:
        return
    print_block_microcode(ea)


if __name__ == "__main__":
    main()
