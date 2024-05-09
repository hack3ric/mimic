% mimic(1) | Mimic Manual

# NAME

mimic - eBPF TCP -> UDP obfuscator

# SYNOPSIS

| `mimic run [OPTION...] <interface>`
| `mimic show [OPTION...] <interface>`

# OPTIONS

**`-?, --help`**
: Give this help list

**`--usage`**
: Give a short usage message

**`-V, --version`**
: Print program version

## mimic run

**`-f, --filter=FILTER`**
: Specify what packets to process. This may be specified for multiple times.

**`-q, --quiet`**
: Output less information

**`-v, --verbose`**
: Output more information

**`-F, --file=PATH`**
: Load configuration from file

## mimic show

**`-c, --connections`**
: Show connections

**`-p, --process`**
: Show process information

# FILTERS

TODO

# CONFIGURATION FILES

TODO

# LICENSE

The project is licensed under GNU General Public License version 2 only (GPL-2.0-only).
