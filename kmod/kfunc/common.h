#ifndef _MIMIC_KMOD_KFUNC_KFUNC_H
#define _MIMIC_KMOD_KFUNC_KFUNC_H

#include <linux/btf.h>  // IWYU pragma: export

#ifndef __bpf_kfunc
#define __bpf_kfunc __used noinline
#endif

#ifndef __bpf_kfunc_start_defs
#define __bpf_kfunc_start_defs()                                          \
  __diag_push();                                                          \
  __diag_ignore_all("-Wmissing-declarations",                             \
                    "Global kfuncs as their definitions will be in BTF"); \
  __diag_ignore_all("-Wmissing-prototypes", "Global kfuncs as their definitions will be in BTF")
#endif

#ifndef __bpf_kfunc_end_defs
#define __bpf_kfunc_end_defs() __diag_pop()
#endif

#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START BTF_SET8_START
#endif

#ifndef BTF_KFUNCS_END
#define BTF_KFUNCS_END BTF_SET8_END
#endif

#endif  // _MIMIC_KMOD_KFUNC_KFUNC_H
