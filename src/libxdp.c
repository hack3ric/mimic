#ifdef MIMIC_USE_LIBXDP

#include <dlfcn.h>
#include <errno.h>
#include <xdp/libxdp.h>

#include "common/try.h"
#include "libxdp.h"

static void *libxdp_dl = NULL;

DLSYM_PROTOTYPE(libxdp_set_print) = NULL;
DLSYM_PROTOTYPE(xdp_program__from_bpf_obj) = NULL;
DLSYM_PROTOTYPE(xdp_program__attach) = NULL;
DLSYM_PROTOTYPE(xdp_program__detach) = NULL;
DLSYM_PROTOTYPE(xdp_program__close) = NULL;

static int dlsym_many_or_warnv(void *dl, va_list ap) {
  void (**fn)(void);

  while ((fn = va_arg(ap, typeof(fn)))) {
    void (*tfn)(void);
    const char *symbol;

    symbol = va_arg(ap, typeof(symbol));

    tfn = (typeof(tfn))dlsym(dl, symbol);
    if (!tfn) ret(-ELIBBAD, "can't find symbol '%s': %s", symbol, dlerror());
    *fn = tfn;
  }

  return 0;
}

static int dlopen_many_sym_or_warn_sentinel(void **dlp, const char *filename, ...) {
  void *dl = NULL;
  int retcode;

  if (*dlp) return 0;

  dl = dlopen(filename, RTLD_NOW | RTLD_NODELETE);
  if (!dl) ret(-EOPNOTSUPP, "%s is not installed: %s", filename, dlerror());

  log_debug("loaded '%s' via dlopen()", filename);

  va_list ap;
  va_start(ap, filename);
  retcode = dlsym_many_or_warnv(dl, ap);
  va_end(ap);
  if (retcode < 0) goto cleanup;

  *dlp = dl;
  return 1;
cleanup:
  if (dl) dlclose(dl);
  return retcode;
}

#define dlopen_many_sym_or_warn(dlp, filename, ...) \
  dlopen_many_sym_or_warn_sentinel(dlp, filename, __VA_ARGS__, NULL)

int dlopen_libxdp() {
  return dlopen_many_sym_or_warn(
    &libxdp_dl, "libxdp.so.1", DLSYM_ARG(libxdp_set_print), DLSYM_ARG(xdp_program__from_bpf_obj),
    DLSYM_ARG(xdp_program__attach), DLSYM_ARG(xdp_program__detach), DLSYM_ARG(xdp_program__close));
}

#endif  // MIMIC_USE_LIBXDP
