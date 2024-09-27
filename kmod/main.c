#include <linux/module.h>

#include "impl.h"

MODULE_VERSION("0.5.0");
MODULE_DESCRIPTION("eBPF TCP -> UDP obfuscator - kernel module extension");
MODULE_LICENSE("GPL");

static int __init mimic_init(void) { return impl_init(); }
static void __exit mimic_exit(void) { impl_exit(); }

module_init(mimic_init);
module_exit(mimic_exit);
