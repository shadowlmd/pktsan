# PKT Sanitizer (pktsan)

Truncates overlong `toUserName`, `fromUserName` and `subject` in FTS-0001
packets (`*.pkt`).

FTS-0001 limits these null-terminated strings to 36, 36 and 72 bytes
including the null. Some software writes longer strings, and tossers that
read the fields into fixed-size buffers, such as FastEcho, break on them.
pktsan runs before the tosser and truncates the strings.

## Processing

- Processes every `*.pkt` file (extension in any case) in the directories
  given on the command line.
- Truncates the strings to 35, 35 and 71 bytes in every message whose
  header can be read, including a last message cut off by the end of the
  file.
- Changes nothing else. Data that does not parse as packed messages
  (unknown message type, missing or short packet terminator, data after the
  last message) is kept byte for byte.
- Skips a file that is not a packet: shorter than a packet header (58
  bytes), or followed by neither packed messages nor a packet terminator.

A packet that needs no changes is not written to. A packet that needs
changes is written to `name.tr$`, then `name.pkt` is deleted, `name.tr$` is
renamed to `name.pkt` and the original file time is restored.

After an interrupted run, the next run:

- deletes `name.tr$` if `name.pkt` exists, and processes `name.pkt` again;
- renames `name.tr$` to `name.pkt` if `name.pkt` does not exist.

## FastEcho

FastEcho runs the "External programs (After Unpack)" command (section
5.4.12.1 of the manual) during `FastEcho TOSS` before tossing any packets,
including when no bundles were unpacked. Enter pktsan there with the
inbound, the unpack directory and the local inbound:

```
c:\ftn\pktsan\pktsan.exe c:\ftn\inbound c:\ftn\inbound\temp c:\ftn\inbound\local
```

Use the directories from your FastEcho setup.

## Command line

```
pktsan [-c config] dir...
```

- `dir`: a directory with packets; at least one. A relative path is relative
  to the current directory.
- `-c config`: the config file.
- `-h`: help.

Without a directory, pktsan prints the help and exits with code 1.

The default config is `pktsan.cfg` in the program directory, or in the
current directory if the program was started without a path. It is
optional. A config given with `-c` must exist.

Exit code:

- 0: no errors;
- 1: bad argument, bad config or log can't be opened (no packets are
  processed), or an error was logged.

## Configuration

```
; pktsan.cfg
LogFile c:\ftn\log\pktsan.log
LogLevel info
```

- `LogFile`: log file, appended to. Default: console. A relative path is
  relative to the config directory. May be in double quotes.
- `LogLevel`:
  - `info` (default): each directory, one line per packet, warnings,
    errors;
  - `warn`: warnings and errors.

Lines starting with `;` or `#` are comments. Keywords are case-insensitive.

## Log

- `[info]`: each directory and the result for each packet.
- `[warn]`: a problem in a processed packet: truncated field, cut off
  message, unparsable data after the last message; also leftover temporary
  files.
- `[err]`: a directory or a file was skipped: not a packet, or a read or
  write error.

File names are logged with the full path.

```
2026-09-26 19:42:46 [info] processing directory c:\ftn\inbound
2026-09-26 19:42:46 [info] processing directory c:\ftn\inbound\temp
2026-09-26 19:42:46 [warn] truncated subject to 71 bytes (was 200) in message #32 in c:\ftn\inbound\temp\1234abcd.pkt
2026-09-26 19:42:46 [info] processed c:\ftn\inbound\temp\1234abcd.pkt: messages 40, modified 1
2026-09-26 19:42:46 [info] processed c:\ftn\inbound\temp\5678ef01.pkt: messages 12, modified 0
2026-09-26 19:42:46 [warn] c:\ftn\inbound\temp\6ab6fb20.pkt: incomplete packet terminator after message #1 (1 byte at offset 662), kept as is
2026-09-26 19:42:46 [info] processed c:\ftn\inbound\temp\6ab6fb20.pkt: messages 1, modified 0
2026-09-26 19:42:46 [err] c:\ftn\inbound\temp\9abc0123.pkt is not a packet: only 12 bytes, shorter than a packet header, skipped
```

## Building

One C file; needs the standard C library, `dirent.h`, `utime()`,
`getcwd()` and `getopt()`.

```
gcc -O2 -static-libgcc -o pktsan.exe pktsan.c     (MinGW, Win32)
gcc -O2 -o pktsan pktsan.c                        (Linux)
```

## Tests

```
make test
```

Linux, Python 3. Runs every test against a normal build and an
AddressSanitizer/UndefinedBehaviorSanitizer build, comparing the output with
a reference implementation. Includes a fuzzer (1500 random and damaged
packets).
