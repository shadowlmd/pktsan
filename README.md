# PKT Sanitizer (pktsan)

pktsan shortens overlong names and subjects in FidoNet packets (`*.pkt`) so
that a tosser can process them.

## Why

FTS-0001 defines three strings in the header of a packed message:
`toUserName`, `fromUserName` and `subject`. Each one is null-terminated and
can hold at most 36, 36 and 72 bytes including the null. That leaves 35, 35
and 71 characters of text. Some software writes longer strings anyway.

Many tossers read these fields as fixed-size buffers. When a string is too
long, its tail is read as the next field, the rest of the message header
shifts, and the tosser breaks. RNtrack did this until RNtrack-AF 2.4.0: it
lost the message text and dropped the rest of the packet.

FastEcho fails on such packets just as hard. Its source code is closed, so it
cannot be fixed. pktsan works around the problem: it runs after FastEcho
unpacks the incoming bundles and before FastEcho tosses the packets. It
truncates the overlong strings, and FastEcho then receives valid packets.

## What it does

- It processes every `*.pkt` file in the given directories, or in the current
  directory if none are given. The `.pkt` extension is matched in any case.
- It reads `toUserName`, `fromUserName` and `subject` up to their terminating
  null, as FTS-0001 requires. It truncates them to 35, 35 and 71 bytes and
  logs a warning for each truncation.
- It changes nothing else. The packet header, the message headers, the
  message texts and the order of messages stay exactly as they were. Any data
  that does not parse as packed messages is copied as is, byte for byte. That
  includes an unknown message type, a cut message, a missing or short packet
  terminator, and garbage after the last message.
- It does not validate packets. Checking signatures, passwords and addresses
  is the tosser's job.

A packet that needs no changes is only read. pktsan does not rewrite it,
rename it or change its timestamp.

A packet that needs changes goes through these steps:

1. pktsan writes the fixed packet to `name.tr$` in the same directory.
2. It deletes `name.pkt`.
3. It renames `name.tr$` to `name.pkt` and restores the original file time.

If a run is interrupted, the next run cleans up after it:

- If `name.tr$` exists next to `name.pkt`, the fixed copy was not finished.
  pktsan deletes `name.tr$`, and the untouched packet is processed again.
- If `name.tr$` exists without `name.pkt`, the fixed copy was complete.
  pktsan renames it back to `name.pkt`.

## Using it with FastEcho

In FastEcho setup, open the "External programs (After Unpack)" field
(section 5.4.12.1 of the FastEcho manual) and enter the pktsan command line.
FastEcho runs this command during `FastEcho TOSS`, after it has unpacked the
incoming mail bundles.

FastEcho may place the unpacked packets in the Inbound, Temporary Inbound and
Local Inbound directories. List all of them on the command line. Use full
paths everywhere: for the program, for the config (`-c`) and for the
directories. Then pktsan works no matter which directory FastEcho starts it
in. For example:

```
c:\ftn\pktsan\pktsan.exe -c c:\ftn\pktsan\pktsan.cfg c:\ftn\inbound c:\ftn\inbound\temp c:\ftn\inbound\local
```

## Command line

```
pktsan [-c config] [directory ...]
```

- `-c config` sets the config file. Without `-c`, pktsan reads `pktsan.cfg`
  from the directory of the program, as found from the command it was started
  with. If you start it without a path, that is the current directory. A
  config named with `-c` must exist. The default config is optional.
- `directory ...` lists the directories to process. The default is the
  current directory.

The exit code is 0 on success. It is 1 if the config is wrong, if the log
cannot be opened, or if any packet could not be processed. If the config is
wrong or the log cannot be opened, pktsan processes no packets at all. Any
packet pktsan could not process is left unchanged.

## Configuration

```
; pktsan.cfg
LogFile c:\ftn\log\pktsan.log
LogLevel info
```

- `LogFile` is the file pktsan appends its log to. Without it, the log goes
  to the console. You may put the path in double quotes.
- `LogLevel` takes one of two values:
  - `info` logs one line for every processed packet, plus all warnings.
  - `warn` logs warnings only. A warning is any problem, fixed or not: a
    truncated field, unparsable data after the last message, a file shorter
    than a packet header, a leftover temporary file, or an error while
    reading or writing a file.

Lines starting with `;` or `#` are comments. Keywords are case-insensitive.

Example log:

```
2026-09-26 19:42:46 [warn] truncated subject to 71 bytes (was 200) in message #32 in c:\ftn\inbound\1234abcd.pkt
2026-09-26 19:42:46 [info] processed c:\ftn\inbound\1234abcd.pkt: 40 messages, 1 fields truncated
2026-09-26 19:42:46 [info] processed c:\ftn\inbound\5678ef01.pkt: 12 messages, nothing truncated
```

## Building

pktsan is one C file. It uses only the standard C library, plus `dirent.h`
and `utime()`, which MinGW, DJGPP and the OS/2 compilers all provide.

```
gcc -O2 -static-libgcc -o pktsan.exe pktsan.c     (MinGW, Win32)
gcc -O2 -o pktsan pktsan.c                        (Linux)
```

## Tests

```
make test
```

The tests run on Linux and need Python 3. They build pktsan twice: a normal
build and one with AddressSanitizer and UndefinedBehaviorSanitizer. Every test
runs against both builds. The tests compare the output with an independent
reference implementation. They cover:

- field boundaries;
- message order;
- broken and cut packets;
- file name matching;
- logging and configuration;
- recovery after an interrupted run;
- a fuzzer that runs 1500 random and damaged packets.
