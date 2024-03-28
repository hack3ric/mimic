#ifndef _MIMIC_SHARED_UTIL_H
#define _MIMIC_SHARED_UTIL_H

#ifdef _MIMIC_BPF
#else
#include <unistd.h>
#include <stdio.h>
#endif

#ifndef MIMIC_RUNTIME_DIR
#define MIMIC_RUNTIME_DIR "/var/mimic"
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))
#define cmp(x, y) ((x) > (y) - (x) < (y))

// Some missing declaration of vmlinux.h
#ifdef _MIMIC_BPF

// defined in linux/pkt_cls.h
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

// defined in linux/if_ether.h
#define ETH_HLEN 14       /* Total octets in header. */
#define ETH_DATA_LEN 1500 /* Max. octets in payload	*/
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook	*/

// defined in linux/tcp.h
#define tcp_flag_word(tp) (((union tcp_word_hdr*)(tp))->words[3])

#endif  // _MIMIC_BPF

// Cleanup utilities
#ifndef _MIMIC_BPF

static inline void cleanup_fd(int* fd) {
  if (*fd >= 0) close(*fd);
}
static inline void cleanup_file(FILE** file) {
  if (*file) fclose(*file);
}

#define _cleanup_fd __attribute__((__cleanup__(cleanup_fd)))
#define _cleanup_file __attribute__((__cleanup__(cleanup_file)))

#endif  // _MIMIC_BPF

// mimic_settings keys
enum settings_key {
  SETTINGS_LOG_VERBOSITY,
  SETTINGS_WHITELIST,  // not stored in mimic_settings map
};

#endif  // _MIMIC_SHARED_UTIL_H
