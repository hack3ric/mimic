#ifndef _MIMIC_KMOD_KPROBE_H
#define _MIMIC_KMOD_KPROBE_H

#ifdef _MIMIC_KMOD
#include <linux/kprobes.h>
#endif

#define MAGIC_FLAG 0x4eb37b03751ff785

#ifdef _MIMIC_KMOD
extern struct kretprobe kp;
#endif

#endif  // _MIMIC_KMOD_KPROBE_H
