// Generated using tools/vendor-vmlinux-h, do not edit!

#ifndef _BPF_VMLINUX_H
#define _BPF_VMLINUX_H

#if defined(MIMIC_BPF_USE_SYSTEM_VMLINUX)
#include "vmlinux/system.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_i386) || defined(MIMIC_BPF_TARGET_ARCH_i486) || defined(MIMIC_BPF_TARGET_ARCH_i586) || defined(MIMIC_BPF_TARGET_ARCH_i686)
#include "vmlinux/i386.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_x86_64)
#include "vmlinux/x86_64.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_arm)
#include "vmlinux/arm.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_aarch64)
#include "vmlinux/aarch64.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_riscv64)
#include "vmlinux/riscv64.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_loongarch64) || defined(MIMIC_BPF_TARGET_ARCH_loong64)
#include "vmlinux/loongarch64.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_ppc) || defined(MIMIC_BPF_TARGET_ARCH_powerpc)
#include "vmlinux/ppc.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_ppc64) || defined(MIMIC_BPF_TARGET_ARCH_powerpc64)
#include "vmlinux/ppc64.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_ppc64le) || defined(MIMIC_BPF_TARGET_ARCH_powerpc64le)
#include "vmlinux/ppc64le.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_mips)
#include "vmlinux/mips.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_mipsel)
#include "vmlinux/mipsel.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_mips64)
#include "vmlinux/mips64.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_mips64el)
#include "vmlinux/mips64el.h"  // IWYU pragma: export
#elif defined(MIMIC_BPF_TARGET_ARCH_s390x)
#include "vmlinux/s390x.h"  // IWYU pragma: export
#else
#include <asm/types.h>       // IWYU pragma: export
#include <linux/bpf.h>       // IWYU pragma: export
#include <linux/if_ether.h>  // IWYU pragma: export
#include <linux/in.h>        // IWYU pragma: export
#include <linux/ip.h>        // IWYU pragma: export
#include <linux/ipv6.h>      // IWYU pragma: export
#include <linux/stddef.h>    // IWYU pragma: export
#include <linux/tcp.h>       // IWYU pragma: export
#include <linux/types.h>     // IWYU pragma: export
#include <linux/udp.h>       // IWYU pragma: export
#include <stdbool.h>         // IWYU pragma: export
#endif

#endif  // _BPF_VMLINUX_H
