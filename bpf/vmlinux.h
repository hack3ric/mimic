// Generated using tools/vendor-vmlinux-h, do not edit!

#ifndef _BPF_VMLINUX_H
#define _BPF_VMLINUX_H

#if defined(_MIMIC_BPF_USE_SYSTEM_VMLINUX)
#include "vmlinux/system.h"  // IWYU pragma: export
#elif defined(_MIMIC_BPF_TARGET_ARCH_x86_64) || defined(_MIMIC_BPF_TARGET_ARCH_amd64)
#include "vmlinux/x86_64.h"  // IWYU pragma: export
#elif defined(_MIMIC_BPF_TARGET_ARCH_aarch64) || defined(_MIMIC_BPF_TARGET_ARCH_arm64)
#include "vmlinux/aarch64.h"  // IWYU pragma: export
#elif defined(_MIMIC_BPF_TARGET_ARCH_riscv64)
#include "vmlinux/riscv64.h"  // IWYU pragma: export
#elif defined(_MIMIC_BPF_TARGET_ARCH_ppc) || defined(_MIMIC_BPF_TARGET_ARCH_powerpc)
#include "vmlinux/ppc.h"  // IWYU pragma: export
#elif defined(_MIMIC_BPF_TARGET_ARCH_ppc64) || defined(_MIMIC_BPF_TARGET_ARCH_powerpc64)
#include "vmlinux/ppc64.h"  // IWYU pragma: export
#elif defined(_MIMIC_BPF_TARGET_ARCH_ppc64le) || defined(_MIMIC_BPF_TARGET_ARCH_powerpc64le)
#include "vmlinux/ppc64le.h"  // IWYU pragma: export
#else
#include "vmlinux/system.h"  // IWYU pragma: export
#endif

#endif  // _BPF_VMLINUX_H
