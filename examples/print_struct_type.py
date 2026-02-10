"""
Print a structure definition with member offsets.

Prompts the user for a structure name, retrieves its type information,
and prints each member with its byte offset in a format similar to
IDA's Structures window.

Example output for "Elf64_Sym":
    00000000 struct Elf64_Sym // sizeof=0x18
    00000000 {
    00000000     unsigned __int32 st_name;
    00000004     unsigned __int8 st_info;
    00000005     unsigned __int8 st_other;
    00000006     unsigned __int16 st_shndx;
    00000008     unsigned __int64 st_value;
    00000010     unsigned __int64 st_size;
    00000018 };

Usage: Run in IDA Pro via File -> Script file...
"""

import ida_kernwin
import ida_typeinf


def print_struct(name):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        print("Type '%s' not found" % name)
        return

    if not (tif.is_struct() or tif.is_union()):
        print("'%s' is not a struct or union" % name)
        return

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        print("Failed to get UDT details for '%s'" % name)
        return

    total_size = tif.get_size()
    kind = "union" if tif.is_union() else "struct"

    print("%08X %s %s // sizeof=0x%X" % (0, kind, name, total_size))
    print("%08X {" % 0)

    for i in range(udt.size()):
        udm = udt[i]
        offset_bytes = udm.offset // 8
        type_str = ida_typeinf.print_tinfo(
            "", 0, 0, ida_typeinf.PRTYPE_1LINE, udm.type, "", ""
        )
        print("%08X     %s %s;" % (offset_bytes, type_str, udm.name))

    print("%08X };" % total_size)


def main():
    name = ida_kernwin.ask_str("", 0, "Enter structure name:")
    if not name:
        return
    print_struct(name)


if __name__ == "__main__":
    main()
