#ifndef __MIMIC_UTIL_H__
#define __MIMIC_UTIL_H__

#include <stdio.h>

#define error_fmt(fmt, ...) fprintf(stderr, "  \e[1;31merror:\e[0m " fmt "\n", ##__VA_ARGS__)

#define ret_with_error(error, ...) \
  ({                               \
    error_fmt(__VA_ARGS__);        \
    return error;                  \
  })

// Requires `cleanup` label, `retcode` to be defined inside function scope, and `retcode` to be
// returned after cleanup.
#define cleanup_with_error(e, ...) \
  ({                               \
    error_fmt(__VA_ARGS__);        \
    retcode = e;                   \
    goto cleanup;                  \
  })

#define try(x)                  \
  ({                            \
    int result = x;             \
    if (result) return -result; \
  })

#define try_msg(x, ...)       \
  ({                          \
    int result = x;           \
    if (result) {             \
      error_fmt(__VA_ARGS__); \
      return -result;         \
    }                         \
  })

#define try_cleanup_msg(x, ...) \
  ({                            \
    int result = x;             \
    if (result) {               \
      error_fmt(__VA_ARGS__);   \
      retcode = -result;        \
      goto cleanup;             \
    }                           \
  })

#define try_ptr(x)         \
  ({                       \
    void* result = x;      \
    if (!result) return 1; \
    result;                \
  })

#define try_ptr_msg(x, ...)   \
  ({                          \
    void* result = x;         \
    if (!result) {            \
      error_fmt(__VA_ARGS__); \
      return 1;               \
    }                         \
    result;                   \
  })

#endif  // __MIMIC_UTIL_H__
