#include <argp.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_types.h>
#include <json-c/json_util.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mimic.h"
#include "shared/gettext.h"
#include "shared/try.h"

struct lock_error {
  enum lock_error_kind {
    ERR_NULL,
    ERR_INVALID_TYPE,
    ERR_NOT_FOUND,
    ERR_VERSION_MISMATCH,
  } kind;
  union {
    struct {
      const char* field;
      json_type expected, got;
    } invalid_type;
    struct {
      const char* field;
    } not_found;
    struct {
      const char* got;
    } version_mismatch;
  };
};

int lock_error_fmt(struct lock_error* error, char* buf, size_t len) {
  switch (error->kind) {
    case ERR_NULL: {
      const char* msg = _("Success");
      strncpy(buf, msg, len);
      return strlen(msg);
    }
    case ERR_INVALID_TYPE:
      return snprintf(buf, len, _("expected %s for field '%s', got %s"),
                      json_type_to_name(error->invalid_type.expected), error->invalid_type.field,
                      json_type_to_name(error->invalid_type.got));
    case ERR_NOT_FOUND:
      return snprintf(buf, len, _("field '%s' not found"), error->not_found.field);
    case ERR_VERSION_MISMATCH:
      return snprintf(buf, len, _("current Mimic version is %s, but lock file's is %s"), argp_program_version,
                      error->version_mismatch.got);
  }
}

static inline struct json_object* lock_serialize(const struct lock_content* c) {
  struct json_object* obj = json_object_new_object();

  int ret = json_object_object_add(obj, "version", json_object_new_string(argp_program_version));
  ret = ret ?: json_object_object_add(obj, "pid", json_object_new_int(c->pid));
  ret = ret ?: json_object_object_add(obj, "egress_id", json_object_new_int(c->egress_id));
  ret = ret ?: json_object_object_add(obj, "ingress_id", json_object_new_int(c->ingress_id));
  ret = ret ?: json_object_object_add(obj, "whitelist_id", json_object_new_int(c->whitelist_id));
  ret = ret ?: json_object_object_add(obj, "settings_id", json_object_new_int(c->settings_id));
  ret = ret ?: json_object_object_add(obj, "conns_id", json_object_new_int(c->conns_id));

  if (ret) {
    json_object_put(obj);
    return NULL;
  }
  return obj;
}

int lock_write(int fd, const struct lock_content* c) {
  struct json_object* lock_json = lock_serialize(c);
  const char* buf = json_object_to_json_string(lock_json);
  size_t buf_len = strlen(buf);
  int result = try_e(write(fd, buf, buf_len), _("failed to write lock file: %s"), strerror(-_ret));
  json_object_put(lock_json);
  if (result < buf_len) {
    ret(-1, _("failed to write lock file: not enough bytes written (expected %lu, got %d)"), buf_len, result);
  }
  return 0;
}

#define _lock_parse_field(_type, _type_val, obj, key, error, errored)                                         \
  struct json_object* field;                                                                                  \
  if (!json_object_object_get_ex(obj, key, &field)) {                                                         \
    if (error) *error = (struct lock_error){.kind = ERR_NOT_FOUND, .not_found.field = key};                   \
    *errored = true;                                                                                          \
    return 0;                                                                                                 \
  }                                                                                                           \
  json_type field_type = json_object_get_type(field);                                                         \
  if (field_type != _type_val) {                                                                              \
    if (error) {                                                                                              \
      *error = (struct lock_error){.kind = ERR_INVALID_TYPE,                                                  \
                                   .invalid_type = {.field = key, .expected = _type_val, .got = field_type}}; \
    }                                                                                                         \
    *errored = true;                                                                                          \
    return 0;                                                                                                 \
  }                                                                                                           \
  return json_object_get_##_type(field);

static inline const char* lock_parse_field_string(const struct json_object* obj, const char* key,
                                                  struct lock_error* error, bool* errored) {
  _lock_parse_field(string, json_type_string, obj, key, error, errored);
}

static inline int lock_parse_field_int(const struct json_object* obj, const char* key, struct lock_error* error,
                                       bool* errored) {
  _lock_parse_field(int, json_type_int, obj, key, error, errored);
}

struct lock_content lock_deserialize(const struct json_object* obj, struct lock_error* error) {
  struct lock_content c = {};
  bool errored = false;
  json_type obj_type = json_object_get_type(obj);
  if (obj_type != json_type_object) {
    if (error) {
      *error = (struct lock_error){.kind = ERR_INVALID_TYPE,
                                   .invalid_type = {.field = NULL, .expected = json_type_object, .got = obj_type}};
    }
    return c;
  }
  const char* version = lock_parse_field_string(obj, "version", error, &errored);
  if (!errored && strcmp(version, argp_program_version) != 0) {
    if (error) {
      *error = (struct lock_error){.kind = ERR_VERSION_MISMATCH, .version_mismatch.got = version};
    }
    return c;
  }
  if (!errored) c.pid = lock_parse_field_int(obj, "pid", error, &errored);
  if (!errored) c.egress_id = lock_parse_field_int(obj, "egress_id", error, &errored);
  if (!errored) c.ingress_id = lock_parse_field_int(obj, "ingress_id", error, &errored);
  if (!errored) c.whitelist_id = lock_parse_field_int(obj, "whitelist_id", error, &errored);
  if (!errored) c.conns_id = lock_parse_field_int(obj, "conns_id", error, &errored);
  if (!errored) c.settings_id = lock_parse_field_int(obj, "settings_id", error, &errored);
  return c;
}

int lock_read(FILE* file, struct lock_content* c) {
  char buf[1024] = {};
  int result = try_e(fread(buf, 1, sizeof(buf), file), _("failed to read lock file: %s"), strerror(-_ret));
  if (result > 1023) ret(-1, _("failed to read lock file: file size too big (> %d)"), 1023);
  buf[result + 1] = '\0';

  enum json_tokener_error parse_error = json_tokener_success;
  struct json_object* obj = try_p(json_tokener_parse_verbose(buf, &parse_error), _("failed to parse lock file: %s"),
                                  json_tokener_error_desc(parse_error));

  struct lock_error lock_error = {};
  *c = lock_deserialize(obj, &lock_error);
  json_object_put(obj);
  if (lock_error.kind != ERR_NULL) {
    lock_error_fmt(&lock_error, buf, 1023);
    ret(-1, _("failed to parse lock file: %s"), buf);
  }

  return 0;
}
