#include <argp.h>

#include "args.h"
#include "run.h"
#include "shared/util.h"
#include "show.h"

int main(int argc, char** argv) {
  struct arguments args = {};
  try(argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &args), "error parsing arguments");

  switch (args.cmd) {
    case CMD_run:
      return subcmd_run(&args.run);
    case CMD_show:
      return subcmd_show(&args.show);
    default:
      break;
  }
  return 0;
}
