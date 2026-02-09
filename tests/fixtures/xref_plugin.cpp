#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <xref.hpp>
#include <funcs.hpp>
#include <name.hpp>

/**
 * Get all cross-references to the given address.
 */
void show_xrefs_to(ea_t target)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target, XREF_ALL); ok; ok = xb.next_to() )
  {
    qstring from_name;
    get_name(&from_name, xb.from);
    func_t *pfn = get_func(xb.from);
    msg("  Xref from %a (%s)\n", xb.from, from_name.c_str());
  }
}

/**
 * Get all cross-references from the given address.
 */
void show_xrefs_from(ea_t source)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_from(source, XREF_ALL); ok; ok = xb.next_from() )
  {
    qstring to_name;
    get_name(&to_name, xb.to);
    func_t *pfn = get_func(xb.to);
    msg("  Xref to %a (%s)\n", xb.to, to_name.c_str());
  }
}
