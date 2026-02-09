#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <entry.hpp>

struct entry_lister_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

bool idaapi entry_lister_t::run(size_t)
{
  size_t qty = get_entry_qty();
  for ( size_t i = 0; i < qty; i++ )
  {
    uval_t ord = get_entry_ordinal(i);
    ea_t ea = get_entry(ord);
    qstring entry_name;
    get_entry_name(&entry_name, ord);
    msg("Entry %d: %s at %a\n", (int)ord, entry_name.c_str(), ea);
  }
  return true;
}

static plugmod_t *idaapi init()
{
  if ( get_entry_qty() == 0 )
    return nullptr;
  return new entry_lister_t;
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_UNL | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  "Entry lister",
  nullptr,
};
