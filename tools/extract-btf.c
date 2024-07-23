// Trying to extract BTF blob from non-ELF Linux kernel image.

#include <assert.h>
#include <linux/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/defs.h"
#include "common/log.h"
#include "common/log_impl.h"  // IWYU pragma: export
#include "common/try.h"

const __u16 BTF_MAGIC_U16 = BTF_MAGIC;

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

  const char* path = argv[1];
  FILE* file _cleanup_file =
    try_p(fopen(path, "rb"), "failed to open file at '%s': %s", path, strret);

  long size = try(get_file_size(file), "failed to get file size: %s", strret);
  char* buf _cleanup_malloc_str = try_p(malloc(size), "cannot malloc: %s", strret);
  try_e(fread(buf, 1, size, file), "failed to read file content: %s", strret);

  struct btf_header* btf_hdr = NULL;
  char *btf_type, *btf_str;

  char *search_ptr, *old_search_ptr = buf;
  size_t remain;
  while ((remain = size - (old_search_ptr - buf)) > sizeof(struct btf_header) &&
         (search_ptr = memmem(old_search_ptr, remain, &BTF_MAGIC_U16, sizeof(__u16)))) {
    struct btf_header* hdr = (typeof(hdr))search_ptr;
    assert(hdr->magic == BTF_MAGIC_U16);

    if (hdr->version != BTF_VERSION || hdr->hdr_len != sizeof(*hdr) ||
        hdr->str_len > BTF_MAX_NAME_OFFSET || hdr->str_len <= 0) {
      goto cont;
    }

    char* type = search_ptr + sizeof(*hdr) + hdr->type_off;
    char* str = search_ptr + sizeof(*hdr) + hdr->str_off;
    if (type + hdr->type_len > buf + size || str + hdr->str_len > buf + size || str[0] != '\0') {
      goto cont;
    }

    log_info("found BTF blob: pos=%lx, flags=%u, type_len=%u, type_off=%u, str_len=%u, str_off=%u",
             search_ptr - buf, hdr->flags, hdr->type_len, hdr->type_off, hdr->str_len,
             hdr->str_off);

    // Select largest BTF blob found, as it is most likely to be vmlinux's
    if (!btf_hdr || btf_hdr->type_len + btf_hdr->str_len < hdr->type_len + hdr->str_len) {
      btf_hdr = hdr;
      btf_type = type;
      btf_str = str;
    }

  cont:
    old_search_ptr = search_ptr + sizeof(__u16);
  }

  // Stitch three parts together
  btf_hdr->type_off = 0;
  btf_hdr->str_off = btf_hdr->type_len;
  fwrite(btf_hdr, 1, sizeof(*btf_hdr), stdout);
  fwrite(btf_type, 1, btf_hdr->type_len, stdout);
  fwrite(btf_str, 1, btf_hdr->str_len, stdout);

  return 0;
}
