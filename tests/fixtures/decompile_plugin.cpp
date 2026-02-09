#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <name.hpp>

struct plugin_ctx_t : public plugmod_t
{
  virtual bool idaapi run(size_t) override;
};

bool idaapi plugin_ctx_t::run(size_t)
{
  ea_t ea = get_screen_ea();
  func_t *pfn = get_func(ea);
  if ( pfn == nullptr )
  {
    msg("No function at current address\n");
    return false;
  }

  qstring func_name;
  get_func_name(&func_name, pfn->start_ea);
  msg("Function: %s at %a\n", func_name.c_str(), pfn->start_ea);

  // Get function bytes
  asize_t size = pfn->size();
  msg("Function size: %d bytes\n", (int)size);

  return true;
}

static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
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
  "Decompile example",
  nullptr,
};
