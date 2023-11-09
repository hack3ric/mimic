#ifndef _MIMIC_UTIL_H
#define _MIMIC_UTIL_H

#include <stdio.h>

#include "log.h"

#define strerrno strerror(errno)

#define ret_with_error(error, ...) \
  ({                               \
    log_error(__VA_ARGS__);        \
    return error;                  \
  })

// Requires `cleanup` label, `retcode` to be defined inside function scope, and `retcode` to be
// returned after cleanup.
#define cleanup_with_error(e, ...) \
  ({                               \
    log_error(__VA_ARGS__);        \
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
      log_error(__VA_ARGS__); \
      return -result;         \
    }                         \
  })

#define try_cleanup_msg(x, ...) \
  ({                            \
    int result = x;             \
    if (result) {               \
      log_error(__VA_ARGS__);   \
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
      log_error(__VA_ARGS__); \
      return 1;               \
    }                         \
    result;                   \
  })

#endif  // _MIMIC_UTIL_H
