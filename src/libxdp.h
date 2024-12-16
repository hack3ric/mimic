#ifndef MIMIC_LIBXDP_H
#define MIMIC_LIBXDP_H

#include <assert.h>
#include <xdp/libxdp.h>

#define DLSYM_PROTOTYPE(symbol) typeof(symbol)* sym_##symbol
#define DLSYM_ARG(arg)                                                     \
  ({                                                                       \
    assert(__builtin_types_compatible_p(typeof(sym_##arg), typeof(&arg))); \
    &sym_##arg;                                                            \
  }),                                                                      \
    #arg

extern DLSYM_PROTOTYPE(libxdp_set_print);
extern DLSYM_PROTOTYPE(xdp_program__from_bpf_obj);
extern DLSYM_PROTOTYPE(xdp_program__attach);
extern DLSYM_PROTOTYPE(xdp_program__detach);
extern DLSYM_PROTOTYPE(xdp_program__close);

int dlopen_libxdp();

#endif
