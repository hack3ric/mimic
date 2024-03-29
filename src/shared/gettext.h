#ifndef _MIMIC_SHARED_GETTEXT_H
#define _MIMIC_SHARED_GETTEXT_H

// Reserved for gettext use in the future.
//
// On eBPF, these markers are just for convenience, so that I can get a comprehensive list of texts. In the future,
// logging should be rewritten so that eBPF should only send structurized information and let userspace call gettext.
#ifndef _MIMIC_BPF
// #define _(text) text
static inline __attribute__((__format_arg__(1))) const char* _(const char* text) { return text; }
#define gettext(text) _(text)
#endif
#define N_(text) text

#endif  // _MIMIC_SHARED_GETTEXT_H
