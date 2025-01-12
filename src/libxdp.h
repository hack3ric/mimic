// Part of this file is derived from systemd, which is licensed under LGPL-2.1-or-later.
//
// Copyright (c) 2020-2024 systemd developers

#ifndef MIMIC_LIBXDP_H
#define MIMIC_LIBXDP_H

#include <assert.h>
#include <xdp/libxdp.h>

#define DLSYM_PROTOTYPE(symbol) typeof(symbol)* sym_##symbol
#define DLSYM_ARG(arg)                                                     \
  ({                                                                       \
    assert(__builtin_types_compatible_p(typeof(sym_##arg), typeof(&arg))); \
    &sym_##arg;                                                            \
  }),                                                                      \
    #arg

#define ELF_NOTE_DLOPEN_VENDOR "FDO"
#define ELF_NOTE_DLOPEN_TYPE UINT32_C(0x407c0c0a)
#define ELF_NOTE_DLOPEN_PRIORITY_REQUIRED "required"
#define ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED "recommended"
#define ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED "suggested"

// Add an ".note.dlopen" ELF note to our binary that declares our weak dlopen() dependency. This
// information can be read from an ELF file via "readelf -p .note.dlopen" or an equivalent command.
#define _ELF_NOTE_DLOPEN(json, variable_name)                                                     \
  __attribute__((used, section(".note.dlopen"))) _Alignas(sizeof(uint32_t)) static const struct { \
    struct {                                                                                      \
      uint32_t n_namesz, n_descsz, n_type;                                                        \
    } nhdr;                                                                                       \
    char name[sizeof(ELF_NOTE_DLOPEN_VENDOR)];                                                    \
    _Alignas(sizeof(uint32_t)) char dlopen_json[sizeof(json)];                                    \
  } variable_name = {                                                                             \
    .nhdr =                                                                                       \
      {                                                                                           \
        .n_namesz = sizeof(ELF_NOTE_DLOPEN_VENDOR),                                               \
        .n_descsz = sizeof(json),                                                                 \
        .n_type = ELF_NOTE_DLOPEN_TYPE,                                                           \
      },                                                                                          \
    .name = ELF_NOTE_DLOPEN_VENDOR,                                                               \
    .dlopen_json = json,                                                                          \
  }

#define _SONAME_ARRAY1(a) "[\"" a "\"]"
#define _SONAME_ARRAY2(a, b) "[\"" a "\",\"" b "\"]"
#define _SONAME_ARRAY3(a, b, c) "[\"" a "\",\"" b "\",\"" c "\"]"
#define _SONAME_ARRAY4(a, b, c, d) \
  "[\""a"\",\""b"\",\""c"\"",\""d"\"]"
#define _SONAME_ARRAY5(a, b, c, d, e) \
  "[\""a"\",\""b"\",\""c"\"",\""d"\",\""e"\"]"
#define _SONAME_ARRAY_GET(_1, _2, _3, _4, _5, NAME, ...) NAME
#define _SONAME_ARRAY(...)                                                                       \
  _SONAME_ARRAY_GET(__VA_ARGS__, _SONAME_ARRAY5, _SONAME_ARRAY4, _SONAME_ARRAY3, _SONAME_ARRAY2, \
                    _SONAME_ARRAY1)                                                              \
  (__VA_ARGS__)

#define UNIQ __COUNTER__
#define XCONCATENATE(a, b) a##b
#define CONCATENATE(a, b) XCONCATENATE(a, b)

// The 'priority' must be one of 'required', 'recommended' or 'suggested' as per specification, use
// the macro defined above to specify it. Multiple sonames can be passed and they will be
// automatically constructed into a json array (but note that due to preprocessor language
// limitations if more than the limit defined above is used, a new _SONAME_ARRAY<X+1> will need to
// be added).
#define ELF_NOTE_DLOPEN(feature, description, priority, ...)                                       \
  _ELF_NOTE_DLOPEN("[{\"feature\":\"" feature "\",\"description\":\"" description                  \
                   "\",\"priority\":\"" priority "\",\"soname\":" _SONAME_ARRAY(__VA_ARGS__) "}]", \
                   CONCATENATE(__elf_note_dlopen_, CONCATENATE(s, UNIQ)))

extern DLSYM_PROTOTYPE(libxdp_set_print);
extern DLSYM_PROTOTYPE(xdp_program__from_bpf_obj);
extern DLSYM_PROTOTYPE(xdp_program__attach);
extern DLSYM_PROTOTYPE(xdp_program__detach);
extern DLSYM_PROTOTYPE(xdp_program__close);

int dlopen_libxdp();

#endif
