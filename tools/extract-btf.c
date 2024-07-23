// Trying to extract BTF blob from non-ELF Linux kernel image.

#include <assert.h>
#include <linux/btf.h>
#include <stdio.h>
#include <string.h>

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

  struct {
    struct btf_header* hdr;
    char *type, *str;
  } cur_btf = {};

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

    if (!cur_btf.hdr ||
        cur_btf.hdr->type_len + cur_btf.hdr->str_len < hdr->type_len + hdr->str_len) {
      cur_btf.hdr = hdr;
      cur_btf.type = type;
      cur_btf.str = str;
    }

  cont:
    old_search_ptr = search_ptr + sizeof(__u16);
  }

  // Stitch three parts together
  cur_btf.hdr->type_off = 0;
  cur_btf.hdr->str_off = cur_btf.hdr->type_len;
  fwrite(cur_btf.hdr, 1, sizeof(*cur_btf.hdr), stdout);
  fwrite(cur_btf.type, 1, cur_btf.hdr->type_len, stdout);
  fwrite(cur_btf.str, 1, cur_btf.hdr->str_len, stdout);

  return 0;
}
