#include <linux/module.h>

#include "csum-hack.h"

MODULE_VERSION("0.5.0");
MODULE_DESCRIPTION("eBPF TCP -> UDP obfuscator - kernel module extension");
MODULE_LICENSE("GPL");

static int __init mimic_init(void) {
  int ret = csum_hack_init();
  return ret;
}

static void __exit mimic_exit(void) { csum_hack_exit(); }

module_init(mimic_init);
module_exit(mimic_exit);
