#ifndef SAMPLE_HPP
#define SAMPLE_HPP

/// Allocate flags for address range.
/// This function does not change the storage type of existing ranges.
/// Exit with an error message if not enough disk space.
/// \param start_ea  should be lower than end_ea.
/// \param end_ea    does not belong to the range.
/// \param stt      storage type
/// \return 0 if ok, otherwise an error code

idaman error_t ida_export enable_flags(ea_t start_ea, ea_t end_ea, storage_type_t stt);


/// Get next address in the program (i.e. next address which has flags).
/// \return BADADDR if no such address exist.

idaman ea_t ida_export next_addr(ea_t ea);


/// Get a pointer to a function structure by address.
/// \param ea  any address in a function
/// \return ptr to a function or nullptr

idaman func_t *ida_export get_func(ea_t ea);


/// A function is a set of continuous ranges of addresses with characteristics
class func_t : public range_t
{
public:
  uint64 flags;
};


/// Delete a function.
/// \param ea  any address in the function
/// \return success

idaman bool ida_export del_func(ea_t ea);

#endif
