#ifndef _MIMIC_RUN_H
#define _MIMIC_RUN_H

#include "args.h"

extern const struct argp run_argp;

int subcmd_run(struct run_arguments* args);

#endif  // _MIMIC_RUN_H
