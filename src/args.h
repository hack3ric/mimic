#ifndef _MIMIC_ARGS_H
#define _MIMIC_ARGS_H

struct arguments {
  enum argument_cmd {
    CMD_NULL = 0,
    CMD_run,
    CMD_show,
    CMD_config,
  } cmd;
  union {
    struct run_arguments {
      char* filters[8];
      unsigned int filter_count;
      char* ifname;
    } run;
    struct show_arguments {
      // TODO
    } show;
  };
};

extern const struct argp argp;

#endif
