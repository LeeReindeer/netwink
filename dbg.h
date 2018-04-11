#ifndef __dbg_h__
#define __dbg_h__

#include <errno.h>
#include <stdio.h>
#include <string.h>

//#define NDEBUG

#ifdef NDEBUG
#define log_d(M, ...)
#else
#define log_d(M, ...)                                                          \
  fprintf(stderr, "[DEBUG] %s:%d " M "\n", __FILE__, __LINE__, ##__VA_ARGS__);
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_e(M, ...)                                                          \
  fprintf(stderr, "[ERROR] (%s:%d: errno:%s)" M "\n", __FILE__, __LINE__,      \
          clean_errno(), ##__VA_ARGS__)

#define log_w(M, ...)                                                          \
  fprintf(stderr, "[WARN] (%s:%d: errno:%s)" M "\n", __FILE__, __LINE__,       \
          clean_errno(), ##__VA_ARGS__)

#define log_i(M, ...)                                                          \
  fprintf(stderr, "[INFO] (%s:%d: errno:%s)" M "\n", __FILE__, __LINE__,       \
          clean_errno(), ##__VA_ARGS__)

#define check(A, M, ...)                                                       \
  if (!(A)) {                                                                  \
    log_e(M, ##__VA_ARGS__);                                                   \
    errno = 0;                                                                 \
    goto error;                                                                \
  }

#define senetinel(M, ...)                                                      \
  {                                                                            \
    log_e(##__VA_ARGS__);                                                      \
    errno = 0;                                                                 \
    goto error;                                                                \
  }

#define check_mem(A) check((A), "Out of memory.")

#define check_debug(A, M, ...)                                                 \
  if (!(A)) {                                                                  \
    debug(M, ##__VA_ARGS__);                                                   \
    errno = 0;                                                                 \
    goto error                                                                 \
  }

// TODO save log to file

#endif //__dbg_h__