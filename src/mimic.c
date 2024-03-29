#include <argp.h>

#include "mimic.h"
#include "shared/try.h"
#include "shared/util.h"

int main(int argc, char** argv) {
  struct arguments args = {};
  try(argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &args), _("error parsing arguments"));

  switch (args.cmd) {
    case CMD_run:
      return -subcmd_run(&args.run);
    case CMD_show:
      return -subcmd_show(&args.show);
    default:
      break;
  }
  return 0;
}
