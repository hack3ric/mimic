#ifndef _MIMIC_KMOD_BTF_H
#define _MIMIC_KMOD_BTF_H

// Taken from newer versions of Linux kernel

#include <linux/btf.h>
#include <linux/btf_ids.h>

#ifndef __bpf_kfunc
#define __bpf_kfunc __used noinline
#endif

#ifndef __bpf_kfunc_start_defs
#define __bpf_kfunc_start_defs()                                                  \
  __diag_push();                                                                  \
  __diag_ignore_all(                                                              \
    "-Wmissing-declarations", "Global kfuncs as their definitions will be in BTF" \
  );                                                                              \
  __diag_ignore_all("-Wmissing-prototypes", "Global kfuncs as their definitions will be in BTF")
#endif

#ifndef __bpf_kfunc_end_defs
#define __bpf_kfunc_end_defs() __diag_pop()
#endif

#endif
