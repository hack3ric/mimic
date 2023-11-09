#ifndef _MIMIC_UTIL_H
#define _MIMIC_UTIL_H

#include <stdio.h>
#include "log.h"

#define strerrno strerror(errno)

#define ret(error, ...)     \
  ({                        \
    log_error(__VA_ARGS__); \
    return error;           \
  })

// Requires `cleanup` label, `retcode` to be defined inside function scope, and `retcode` to be
// returned after cleanup.
#define cleanup(e, ...)     \
  ({                        \
    log_error(__VA_ARGS__); \
    retcode = e;            \
    goto cleanup;           \
  })

#define _get_macro(_0, _1, _2, _3, _4, _5, NAME, ...) NAME

#define try(...) _get_macro(_0, ##__VA_ARGS__, _trym, _trym, _trym, _trym, _try, )(__VA_ARGS__)
#define _try(x)         \
  ({                    \
    int _x = x;         \
    if (_x) return -_x; \
  })
#define _trym(x, ...)              \
  ({                               \
    int _x = x;                    \
    if (_x) ret(-_x, __VA_ARGS__); \
  })

// Jump to cleanup if failed.
#define try_or_cleanup(...) \
  _get_macro(_0, ##__VA_ARGS__, _tryjm, _tryjm, _tryjm, _tryjm, _tryj, )(__VA_ARGS__)
#define _tryj(x)     \
  ({                 \
    int _x = x;      \
    if (_x) {        \
      retcode = -_x; \
      goto cleanup;  \
    }                \
  })
#define _tryjm(x, ...)                     \
  ({                                       \
    int _x = x;                            \
    if (_x) cleanup(-result, __VA_ARGS__); \
  })

// Similar to `try`, but for function that returns a pointer.
#define try_ptr(...) \
  _get_macro(_0, ##__VA_ARGS__, _trypm, _trypm, _trypm, _trypm, _tryp, )(__VA_ARGS__)
#define _tryp(x)       \
  ({                   \
    void* _x = x;      \
    if (!_x) return 1; \
    _x;                \
  })
#define _trypm(x, ...)            \
  ({                              \
    void* _x = x;                 \
    if (!_x) ret(1, __VA_ARGS__); \
    _x;                           \
  })

#endif  // _MIMIC_UTIL_H
