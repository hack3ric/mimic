#ifndef __MIMIC_UTIL_H__
#define __MIMIC_UTIL_H__

#include <stdio.h>

#define error_fmt(fmt, ...) fprintf(stderr, "\033[1;31merror:\033[0m " fmt "\n", ##__VA_ARGS__)

#define exit_with_error(error, ...) \
  ({                                \
    error_fmt(__VA_ARGS__);         \
    exit(error);                    \
  })

#define try(x)                 \
  ({                           \
    int result = x;            \
    if (result) return result; \
  })

#define try_msg(x, ...)       \
  ({                          \
    int result = x;           \
    if (result) {             \
      error_fmt(__VA_ARGS__); \
      return result;          \
    }                         \
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
