r"""
Routines for working with functions within the disassembled program.

This is a minimal SWIG stub fixture for testing.
"""

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")


FUNC_TAIL = 0x0001


class func_t(object):
    r"""
    Proxy of C++ func_t class.
    This class represents a function in the disassembled program.
    """

    def __init__(self, *args):
        r"""
        __init__(self, start=0, size=0) -> func_t
        Create a new function object.

        @param start: (C++: ea_t) start address of the function
        @param size: (C++: asize_t) size of the function
        """
        pass

    def is_far(self, *args) -> "bool":
        r"""
        is_far(self) -> bool
        Is a far function?

        @return: true if the function is far
        """
        pass


def get_func(*args) -> "func_t *":
    r"""
    get_func(ea) -> func_t
    Get pointer to function structure by address.

    @param ea: (C++: ea_t) any address in a function
    @return: ptr to a function or nullptr. This function returns a function entry
             chunk.
    """
    pass


def get_func_name(*args) -> "qstring":
    r"""
    get_func_name(ea) -> str
    Get function name by address.

    @param ea: (C++: ea_t) any address belonging to the function
    @return: length of the function name
    """
    pass


def get_func_qty(*args) -> "size_t":
    r"""
    get_func_qty() -> size_t
    Get total number of functions in the program.

    @return: number of functions
    """
    pass


def add_func(*args) -> "bool":
    r"""
    add_func(ea1, ea2=BADADDR) -> bool
    Add a new function.

    @param ea1: (C++: ea_t) start address
    @param ea2: (C++: ea_t) end address (BADADDR means IDA will try to determine it)
    @return: success
    """
    pass


def del_func(*args) -> "bool":
    r"""
    del_func(ea) -> bool
    Delete a function.

    @param ea: (C++: ea_t) any address in the function
    @return: success
    """
    pass
