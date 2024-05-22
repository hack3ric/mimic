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

**`-q, --quiet`**
: Output less information

**`-v, --verbose`**
: Output more information

**`-f, --filter=FILTER`**
: Specify what packets to process. This may be specified for multiple times. (see [**CONFIGURATION/Filters**](#filters))

**`-h, --handshake`**
: Controls retry behaviour of initiating connection (see [**CONFIGURATION/Handshake and Keepalive Parameters**](#handshake-and-keepalive-parameters))

**`-k, --keepalive`**
: Controls keepalive mechanism (see [**CONFIGURATION/Handshake and Keepalive Parameters**](#handshake-and-keepalive-parameters))

**`-F, --file=PATH`**
: Load configuration from file

## mimic show

**`-c, --connections`**
: Show connections

**`-p, --process`**
: Show process information

# CONFIGURATION

Mimic allows configuration from both command line and configuration file.

## Filters

A filter is an entry of whitelist that looks like a key-value pair: **`{origin}={ip}:{port}`**. Origin is either **local** or **remote**, indicating which side's IP and port is matched. For example, **`remote=192.0.2.1:6000`** matches the server's IP (192.0.2.1) and its listening port (6000).

For IPv6, the IP field needs to be surrounded by square brackets: **`local=[2001:db8::cafe]:7000`**. This means packets originated from or sending to the local machine using that IP and port is processed.

Additionally, settings that overrides global ones can be appended to the back of a filter, such as handshake and keepalive parameters (see [**Handshake and Keepalive Parameters**](#handshake-and-keepalive-parameters)):

```
local=[fd42:d42:d42:d42::1]:20001,keepalive=60:1:3
remote=169.254.42.1:11451,handshake=3:3,keepalive=:1:
```

## Handshake and Keepalive Parameters

Handshake and keepalive parameters are both specified using unsigned numbers separated by colons (**`:`**). Duration fields are specified in seconds.

Handshake parameters **`interval:retry`** specifies duration between each handshake (SYN) retry, and the maximum retry count before giving up.

Keepalive parameters **`time:interval:retry`** specifies duration between last peer activity (i.e. receiving packets) and sending keepalive, duration between keepalive attempt without peer acknowledgement, and the maximum retry count before giving up. **`time`** of 0 turns off keepalive mechanism. **`interval`** of 0 disables keepalive and resets immediately after **`time`** has passed.

Numbers can be left out to fall back to default or global respective values:

```
handshake=:0     # give up immediately after default interval value and do not retry
keepalive=60::   # set keepalive time to 60s only, keeping default values of other fields
```

## Configuration File

Configuration file passed using the **`--file`** contains lines of key-value pair in the format of **`{key}={value}`**. There might be spaces between key, **`=`** and value. Each pair should be contained in one line:

```
# Print more information because we can
log.verbosity = trace

# Keep it more alive!
keepalive = 15::

# You only shake hands once
filter = local=192.0.2.1:6789,handshake=5:0
```

See **/etc/mimic/eth0.conf.example** for detailed examples.

### Available Keys

**`log.verbosity`**
:     Controls how much information should be printed. Log level equal to or higher (in number) than log verbosity will be discarded. Both number and string matching log levels are accepted. Number must be greater than or equal to 0. Defaults to info (2).

    | Available levels are:
    |     0 - error (cannot be discarded)
    |     1 - warn
    |     2 - info
    |     3 - debug
    |     4 - trace

**`handshake`, `keepalive`**
: See [**Handshake and Keepalive Parameters**](#handshake-and-keepalive-parameters).

**`filter`**
: See [**Filters**](#filters). This option may be specified more than once.

# LICENSE

The project is licensed under GNU General Public License version 2 only (GPL-2.0-only).
