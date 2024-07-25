// Try to extract BTF blob from non-ELF Linux kernel image.

#define _GNU_SOURCE

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <linux/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/defs.h"
#include "common/log.h"
#include "common/log_impl.h"  // IWYU pragma: export
#include "common/try.h"

enum endianness {
  E_BIG_ENDIAN,
  E_LITTLE_ENDIAN,
  E_NATIVE_ENDIAN,
};

const char BTF_MAGIC_LE[] = {BTF_MAGIC & 0xff, BTF_MAGIC >> 8};
const char BTF_MAGIC_BE[] = {BTF_MAGIC >> 8, BTF_MAGIC & 0xff};

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline __u16 x16toh(enum endianness x, __u16 i) {
  return x == E_BIG_ENDIAN ? be16toh(i) : i;
}
static inline __u32 x32toh(enum endianness x, __u32 i) {
  return x == E_BIG_ENDIAN ? be32toh(i) : i;
}
// static inline __u16 htox16(enum endianness x, __u16 i) {
//   return x == E_BIG_ENDIAN ? htobe16(i) : i;
// }
// static inline __u32 htox32(enum endianness x, __u32 i) {
//   return x == E_BIG_ENDIAN ? htobe32(i) : i;
// }
static inline const char* btf_magic(enum endianness x) {
  return x == E_BIG_ENDIAN ? BTF_MAGIC_BE : BTF_MAGIC_LE;
}

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline __u16 x16toh(enum endianness x, __u16 i) {
  return x == E_LITTLE_ENDIAN ? le16toh(i) : i;
}
static inline __u32 x32toh(enum endianness x, __u32 i) {
  return x == E_LITTLE_ENDIAN ? le32toh(i) : i;
}
// static inline __u16 htox16(enum endianness x, __u16 i) {
//   return x == E_LITTLE_ENDIAN ? htole16(i) : i;
// }
// static inline __u32 htox32(enum endianness x, __u32 i) {
//   return x == E_LITTLE_ENDIAN ? htole32(i) : i;
// }
static inline const char* btf_magic(enum endianness x) {
  return x == E_LITTLE_ENDIAN ? BTF_MAGIC_LE : BTF_MAGIC_EE;
}

#else
#error unknown target endianness
#endif

long get_file_size(FILE* file) {
  long orig_pos, size;
  orig_pos = try_e(ftell(file));
  try_e(fseek(file, 0, SEEK_END));
  size = try_e(ftell(file));
  try_e(fseek(file, orig_pos, SEEK_SET));
  return size;
}

int main(int argc, char** argv) {
  if (argc < 2) ret(-1, "not enough arguments");

  enum endianness x;
  if (argc == 2)
    x = E_NATIVE_ENDIAN;
  else if (strcmp(argv[2], "le") == 0)
    x = E_LITTLE_ENDIAN;
  else if (strcmp(argv[2], "be") == 0)
    x = E_BIG_ENDIAN;
  else
    ret(-1, "unknown endianness '%s'", argv[2]);

  const char* path = argv[1];
  FILE* file _cleanup_file =
    try_p(fopen(path, "rb"), "failed to open file at %s: %s", path, strret);

  long size = try(get_file_size(file), "failed to get file size: %s", strret);
  char* buf _cleanup_malloc_str = try_p(malloc(size), "cannot malloc: %s", strret);
  try_e(fread(buf, 1, size, file), "failed to read file content: %s", strret);

  struct btf_header* btf_hdr = NULL;
  char *btf_type, *btf_str;

  char *search_ptr, *old_search_ptr = buf;
  size_t remain;
  while ((remain = size - (old_search_ptr - buf)) > sizeof(struct btf_header) &&
         (search_ptr = memmem(old_search_ptr, remain, btf_magic(x), sizeof(__u16)))) {
    struct btf_header* hdr = (typeof(hdr))search_ptr;
    assert(x16toh(x, hdr->magic) == BTF_MAGIC);

    __u32 hdr_len = x32toh(x, hdr->hdr_len);
    __u32 type_off = x32toh(x, hdr->type_off), type_len = x32toh(x, hdr->type_len);
    __u32 str_off = x32toh(x, hdr->str_off), str_len = x32toh(x, hdr->str_len);

    if (hdr->version != BTF_VERSION || str_len > BTF_MAX_NAME_OFFSET) {
      goto cont;
    }

    if (hdr->version != BTF_VERSION || hdr_len != sizeof(*hdr) || str_len > BTF_MAX_NAME_OFFSET ||
        str_len <= 0) {
      goto cont;
    }

    char* type = search_ptr + sizeof(*hdr) + type_off;
    char* str = search_ptr + sizeof(*hdr) + str_off;
    if (type + type_len > buf + size || str + str_len > buf + size || str[0] != '\0') {
      goto cont;
    }

    log_info("found BTF blob: pos=%lx, flags=%u, type_len=%u, type_off=%u, str_len=%u, str_off=%u",
             search_ptr - buf, hdr->flags, type_len, type_off, str_len, str_off);

    // Select largest BTF blob found, as it is most likely to be vmlinux's
    if (!btf_hdr ||
        x32toh(x, btf_hdr->type_len) + x32toh(x, btf_hdr->str_len) < type_len + str_len) {
      btf_hdr = hdr;
      btf_type = type;
      btf_str = str;
    }

  cont:
    old_search_ptr = search_ptr + sizeof(__u16);
  }

  if (!btf_hdr) ret(-ENOENT, "no BTF blob found");

  // Stitch three parts together
  btf_hdr->type_off = 0;
  btf_hdr->str_off = btf_hdr->type_len;
  fwrite(btf_hdr, 1, sizeof(*btf_hdr), stdout);
  fwrite(btf_type, 1, x32toh(x, btf_hdr->type_len), stdout);
  fwrite(btf_str, 1, x32toh(x, btf_hdr->str_len), stdout);

  return 0;
}
