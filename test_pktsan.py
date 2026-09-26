#!/usr/bin/env python3
"""Tests for pktsan. Usage: test_pktsan.py ./pktsan [-v] [-k name]"""

import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

EXE = None
VERBOSE = False
LIMITS = (36, 36, 72)
NAMES = ("toUserName", "fromUserName", "subject")

# ---------------------------------------------------------------- packets


def pkt_header(seed=0):
    rnd = random.Random(seed)
    return bytes(rnd.randrange(256) for _ in range(56)) + b"\x02\x00"


def pmsg(to=b"All", frm=b"Sysop", subj=b"Hello", text=b"Text\r",
         date=b"26 Sep 26  17:00:00\0", hdr=None):
    if hdr is None:
        hdr = struct.pack("<HHHHHHH", 2, 1, 2, 5020, 5030, 0x0100, 0)
    assert len(hdr) == 14 and len(date) == 20
    return hdr + date + to + b"\0" + frm + b"\0" + subj + b"\0" + text + b"\0"


def packet(msgs, tail=b"\0\0", seed=0):
    return pkt_header(seed) + b"".join(msgs) + tail


def reference_tail(data):
    """Offset of the data after the last complete message."""
    p = 58
    while len(data) - p >= 34 and data[p:p + 2] == b"\x02\x00":
        q = p + 34
        for _ in range(4):
            z = data.find(b"\0", q)
            if z < 0:
                return p
            q = z + 1
        p = q
    return p


def reference(data):
    """Independent model: returns (output, msgs, [(msg, field, len)])."""
    if len(data) < 58:
        return data, 0, []
    out = bytearray(data[:58])
    p, n, tr = 58, 0, []
    while len(data) - p >= 34 and data[p:p + 2] == b"\x02\x00":
        q = p + 34
        fields = []
        for _ in range(4):
            z = data.find(b"\0", q)
            if z < 0:
                break
            fields.append(data[q:z])
            q = z + 1
        if len(fields) < 4:
            break
        n += 1
        out += data[p:p + 34]
        for i, f in enumerate(fields):
            if i < 3 and len(f) > LIMITS[i] - 1:
                tr.append((n, i, len(f)))
                f = f[:LIMITS[i] - 1]
            out += f + b"\0"
        p = q
    out += data[p:]
    return bytes(out), n, tr


# ---------------------------------------------------------------- harness


class Env:
    def __init__(self, cfg="LogLevel info\n", with_log=True):
        self.root = tempfile.mkdtemp(prefix="pktsan-")
        self.dir = os.path.join(self.root, "in")
        os.mkdir(self.dir)
        self.log = os.path.join(self.root, "pktsan.log")
        self.cfg = os.path.join(self.root, "test.cfg")
        with open(self.cfg, "w") as f:
            if with_log:
                f.write("LogFile %s\n" % self.log)
            f.write(cfg)

    def put(self, name, data, mtime=1000000000):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as f:
            f.write(data)
        os.utime(path, (mtime, mtime))
        return path

    def get(self, name):
        with open(os.path.join(self.dir, name), "rb") as f:
            return f.read()

    def run(self, args=None, cwd=None, cfg=True):
        cmd = [EXE] + (["-c", self.cfg] if cfg else []) + (args or [])
        r = subprocess.run(cmd, cwd=cwd or self.dir, capture_output=True)
        if VERBOSE:
            print("   ", cmd, r.returncode, r.stdout, r.stderr)
        if b"Sanitizer" in r.stderr or b"runtime error" in r.stderr:
            raise AssertionError("sanitizer: " + r.stderr.decode(errors="replace"))
        return r

    def logtext(self):
        if not os.path.exists(self.log):
            return ""
        with open(self.log) as f:
            return f.read()

    def loglines(self, level=None):
        res = []
        for line in self.logtext().splitlines():
            m = re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \[(\w+)\] (.*)$", line)
            assert m, "bad log line: %r" % line
            assert m.group(1) == "warn" or m.group(2).startswith("processed "), line
            if level is None or m.group(1) == level:
                res.append((m.group(1), m.group(2)))
        return res

    def files(self):
        return sorted(os.listdir(self.dir))

    def cleanup(self):
        for d, _, _ in os.walk(self.root):
            os.chmod(d, 0o755)
        shutil.rmtree(self.root)


def warn_lines(tr, name):
    return ["truncated %s to %d bytes (was %d) in message #%d in %s" %
            (NAMES[f], LIMITS[f] - 1, ln, m, name) for m, f, ln in tr]


def check_packet(env, name, data, r=None):
    """Process one packet and compare with the reference model."""
    path = env.put(name, data)
    ino = os.stat(path).st_ino
    if r is None:
        r = env.run()
    assert r.returncode == 0, r
    exp, n, tr = reference(data)
    got = env.get(name)
    assert got == exp, "output differs from reference"
    st = os.stat(path)
    assert st.st_mtime == 1000000000, "mtime not preserved"
    if not tr:
        assert st.st_ino == ino, "unchanged packet was rewritten"
    assert [l[1] for l in env.loglines("warn")
            if l[1].startswith("truncated ")] == warn_lines(tr, name)
    other = [l[1] for l in env.loglines("warn") if not l[1].startswith("truncated ")]
    tail_ok = len(data) >= 58 and len(data) - reference_tail(data) == 2 and data.endswith(b"\0\0")
    assert bool(other) == (not tail_ok), other
    assert not [f for f in env.files() if f.lower().endswith("$")], env.files()
    return n, tr


TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn

# ---------------------------------------------------------------- cases


@test
def no_changes():
    env = Env()
    data = packet([pmsg(), pmsg(to=b"A" * 35, frm=b"B" * 35, subj=b"C" * 71)])
    n, tr = check_packet(env, "0001.pkt", data)
    assert n == 2 and tr == []
    assert env.loglines() == [("info", "processed 0001.pkt: 2 messages, nothing truncated")]
    env.cleanup()


@test
def boundaries():
    for f in range(3):
        for extra in (0, 1, 2, 500):
            env = Env()
            vals = [b"x", b"y", b"z"]
            vals[f] = bytes(range(0x80, 0x80 + 1)) * (LIMITS[f] - 1 + extra)
            data = packet([pmsg(), pmsg(*vals), pmsg()])
            n, tr = check_packet(env, "b.pkt", data)
            assert n == 3
            assert tr == ([(2, f, LIMITS[f] - 1 + extra)] if extra else [])
            env.cleanup()


@test
def all_fields_long_log_format():
    env = Env()
    data = packet([pmsg(), pmsg(to=b"T" * 40, frm=b"F" * 36, subj=b"S" * 200,
                                text=b"\x01MSGID: 1:2/3 1\rbody\r")])
    n, tr = check_packet(env, "ab.pkt", data)
    assert tr == [(2, 0, 40), (2, 1, 36), (2, 2, 200)]
    assert env.loglines("warn")[2][1] == \
        "truncated subject to 71 bytes (was 200) in message #2 in ab.pkt"
    assert env.loglines("info")[-1][1] == "processed ab.pkt: 2 messages, 3 fields truncated"
    env.cleanup()


@test
def order_preserved_many_messages():
    rnd = random.Random(1)
    msgs, texts = [], []
    for i in range(300):
        t = ("message %d\r" % i).encode() * rnd.randrange(1, 50)
        texts.append(t)
        msgs.append(pmsg(to=b"t" * rnd.choice([0, 5, 35, 36, 90]),
                         frm=b"f" * rnd.choice([0, 35, 36, 37]),
                         subj=b"s" * rnd.choice([0, 71, 72, 300]), text=t))
    env = Env()
    n, tr = check_packet(env, "many.pkt", packet(msgs))
    assert n == 300 and tr
    out = env.get("many.pkt")
    pos = [out.find(t + b"\0") for t in texts]
    assert all(p > 0 for p in pos) and pos == sorted(pos)
    env.cleanup()


@test
def empty_fields_and_text():
    env = Env()
    data = packet([pmsg(b"", b"", b"", b""), pmsg(subj=b"Q" * 80, text=b""),
                   pmsg(b"", b"", b"", b"")])
    n, tr = check_packet(env, "e.pkt", data)
    assert n == 3 and tr == [(2, 2, 80)]
    env.cleanup()


@test
def big_text():
    env = Env()
    text = random.Random(2).randbytes(3 * 1024 * 1024).replace(b"\0", b"x")
    data = packet([pmsg(subj=b"S" * 100, text=text), pmsg()])
    n, tr = check_packet(env, "big.pkt", data)
    assert n == 2 and tr == [(1, 2, 100)]
    env.cleanup()


@test
def terminators():
    long = pmsg(to=b"L" * 50)
    for tail in (b"\0\0", b"\0", b"", b"\0\0\0\0", b"\0\0garbage",
                 b"\x01\x00junk", b"\x02", b"\x02\x00", b"\x02\x00" + b"x" * 40):
        env = Env()
        n, tr = check_packet(env, "t.pkt", packet([pmsg(), long], tail=tail))
        assert n == 2 and tr == [(2, 0, 50)], tail
        warns = [l[1] for l in env.loglines("warn")]
        if tail == b"\0\0":
            assert not [w for w in warns if "terminator" in w]
        else:
            assert [w for w in warns if "not a packet terminator" in w], warns
        env.cleanup()


@test
def incomplete_last_message():
    base = packet([pmsg(frm=b"F" * 60)], tail=b"")
    last = pmsg(to=b"T" * 80, frm=b"F" * 80, subj=b"S" * 80, text=b"text")
    for cut in range(0, len(last)):
        env = Env()
        n, tr = check_packet(env, "i.pkt", base + last[:cut])
        # the incomplete message is copied as is, even with long fields
        assert n == 1 and tr == [(1, 1, 60)], cut
        env.cleanup()


@test
def unknown_message_type_stops_parsing():
    bad = pmsg(to=b"X" * 90, hdr=struct.pack("<HHHHHHH", 3, 1, 2, 3, 4, 5, 6))
    env = Env()
    data = packet([pmsg(to=b"A" * 40), bad, pmsg(to=b"B" * 40)])
    n, tr = check_packet(env, "u.pkt", data)
    assert n == 1 and tr == [(1, 0, 40)]
    env.cleanup()


@test
def short_files():
    for size in (0, 1, 2, 57, 58, 59, 60, 91, 92):
        env = Env()
        data = (packet([pmsg(to=b"Z" * 50)]))[:size]
        n, tr = check_packet(env, "s.pkt", data)
        assert tr == []
        if size < 58:
            assert [l for l in env.loglines("warn") if "shorter than a packet header" in l[1]]
        env.cleanup()


@test
def file_name_matching():
    env = Env()
    long = packet([pmsg(subj=b"S" * 90)])
    names = ["a.pkt", "B.PKT", "c.Pkt", "d.pKt", "e.pkt.bak", "f.pk", "g.pkt~",
             "h.pk$x", "pkt", "i_pkt", ".pkt"]
    for nm in names:
        env.put(nm, long)
    os.mkdir(os.path.join(env.dir, "dir.pkt"))
    r = env.run()
    assert r.returncode == 0, r
    exp = reference(long)[0]
    for nm in names:
        should = nm.lower().endswith(".pkt")
        assert (env.get(nm) == exp) == should, nm
    assert os.path.isdir(os.path.join(env.dir, "dir.pkt"))
    assert len(env.loglines("warn")) == 5
    env.cleanup()


@test
def log_level_warn():
    env = Env(cfg="LogLevel warn\n")
    env.put("1.pkt", packet([pmsg()]))
    env.put("2.pkt", packet([pmsg(to=b"x" * 36)]))
    env.put("3.pkt", packet([pmsg()], tail=b"\0"))
    assert env.run().returncode == 0
    assert env.loglines() == [
        ("warn", "truncated toUserName to 35 bytes (was 36) in message #1 in 2.pkt"),
        ("warn", "3.pkt: 1 bytes after message #1 (offset %d) are not a packet terminator, left unchanged" % (58 + len(pmsg())))]
    env.cleanup()


@test
def log_level_info_lists_all_packets():
    env = Env()
    for i in range(5):
        env.put("%d.pkt" % i, packet([pmsg(subj=b"s" * (70 + i))]))
    assert env.run().returncode == 0
    infos = [l[1] for l in env.loglines("info")]
    assert len([i for i in infos if i.startswith("processed ")]) == 5
    assert len(env.loglines("warn")) == 3
    env.cleanup()


@test
def log_appends():
    env = Env()
    env.put("1.pkt", packet([pmsg()]))
    env.run()
    env.run()
    assert len(env.loglines()) == 2
    env.cleanup()


@test
def config_handling():
    env = Env()
    env.put("1.pkt", packet([pmsg(to=b"x" * 40)]))
    orig = env.get("1.pkt")
    # explicit missing config: error, nothing processed
    r = subprocess.run([EXE, "-c", env.cfg + ".none"], cwd=env.dir, capture_output=True)
    assert r.returncode == 1 and b"can't open config" in r.stderr
    # bad lines: error, nothing processed
    for bad in ("LogLevel debug\n", "Foo bar\n", "LogLevel\n"):
        with open(env.cfg, "w") as f:
            f.write(bad)
        r = env.run()
        assert r.returncode == 1 and b"bad line" in r.stderr, (bad, r)
    assert env.get("1.pkt") == orig
    # unopenable log: error, nothing processed
    with open(env.cfg, "w") as f:
        f.write("LogFile %s\n" % os.path.join(env.root, "no", "such.log"))
    r = env.run()
    assert r.returncode == 1 and b"can't open log" in r.stderr
    assert env.get("1.pkt") == orig
    # comments, CRLF, quotes, spaces in the log path, case of keys
    log = os.path.join(env.root, "log dir", "p t.log")
    os.mkdir(os.path.dirname(log))
    with open(env.cfg, "wb") as f:
        f.write(b"; comment\r\n# comment\r\n\r\n  logfile   \"%s\"  \r\nLOGLEVEL Warn\r\n"
                % log.encode())
    r = env.run()
    assert r.returncode == 0, r
    with open(log) as f:
        text = f.read()
    assert "[warn] truncated toUserName" in text and "[info]" not in text
    env.cleanup()


@test
def default_config_next_to_program():
    env = Env()
    bindir = os.path.join(env.root, "bin")
    os.mkdir(bindir)
    exe = os.path.join(bindir, "pktsan")
    shutil.copy(EXE, exe)
    with open(os.path.join(bindir, "pktsan.cfg"), "w") as f:
        f.write("LogFile %s\nLogLevel info\n" % env.log)
    env.put("1.pkt", packet([pmsg(to=b"x" * 40)]))
    r = subprocess.run([exe], cwd=env.dir, capture_output=True)
    assert r.returncode == 0 and r.stdout == b"", r
    assert "processed 1.pkt" in env.logtext()
    # no config at all: defaults, log to stdout
    os.remove(os.path.join(bindir, "pktsan.cfg"))
    r = subprocess.run([exe], cwd=env.dir, capture_output=True)
    assert r.returncode == 0 and b"[info] processed 1.pkt: 1 messages, nothing truncated" in r.stdout, r
    env.cleanup()


@test
def directories_as_arguments():
    env = Env()
    d2 = os.path.join(env.root, "in2")
    os.mkdir(d2)
    env.put("1.pkt", packet([pmsg(to=b"x" * 40)]))
    with open(os.path.join(d2, "2.pkt"), "wb") as f:
        f.write(packet([pmsg(frm=b"y" * 40)]))
    r = env.run([env.dir, d2 + "/"], cwd=env.root)
    assert r.returncode == 0, r
    warns = [l[1] for l in env.loglines("warn")]
    assert warns == ["truncated toUserName to 35 bytes (was 40) in message #1 in %s/1.pkt" % env.dir,
                     "truncated fromUserName to 35 bytes (was 40) in message #1 in %s/2.pkt" % d2]
    r = env.run([os.path.join(env.root, "nodir")])
    assert r.returncode == 1 and "can't read directory" in env.logtext()
    env.cleanup()


@test
def temp_files_from_interrupted_run():
    env = Env()
    data = packet([pmsg(to=b"x" * 40)])
    env.put("1.pkt", data)
    env.put("1.tr$", b"incomplete")      # write was interrupted: delete
    env.put("2.PKT", packet([pmsg()]))
    env.put("2.TR$", b"incomplete")
    env.put("3.tr$", data)               # interrupted after delete: restore
    assert env.run().returncode == 0
    assert env.files() == ["1.pkt", "2.PKT", "3.pkt"], env.files()
    assert env.get("1.pkt") == env.get("3.pkt") == reference(data)[0]
    assert [l for l in env.loglines("warn") if "temporary" in l[1]] == [
        ("warn", "deleted incomplete temporary file 1.tr$"),
        ("warn", "deleted incomplete temporary file 2.TR$"),
        ("warn", "restored 3.pkt from temporary file 3.tr$")]
    assert "processed 3.pkt: 1 messages, 1 fields truncated" in env.logtext()
    env.cleanup()


@test
def mtime_preserved():
    env = Env()
    path = env.put("1.pkt", packet([pmsg(to=b"x" * 40)]), mtime=1234567890)
    assert env.run().returncode == 0
    assert os.stat(path).st_mtime == 1234567890
    env.cleanup()


@test
def read_only_directory():
    if os.geteuid() == 0:
        return
    env = Env()
    data = packet([pmsg(to=b"x" * 40)])
    env.put("1.pkt", data)
    env.put("2.pkt", packet([pmsg()]))
    os.chmod(env.dir, 0o555)
    r = env.run()
    os.chmod(env.dir, 0o755)
    assert r.returncode == 1
    assert env.get("1.pkt") == data and env.files() == ["1.pkt", "2.pkt"]
    assert [l[1] for l in env.loglines("warn")] == [
        "can't write 1.tr$: Permission denied, 1.pkt left unchanged"]
    assert [l[1] for l in env.loglines("info")] == ["processed 2.pkt: 1 messages, nothing truncated"]
    env.cleanup()


@test
def unreadable_packet_does_not_stop_others():
    if os.geteuid() == 0:
        return
    env = Env()
    p1 = env.put("1.pkt", packet([pmsg(to=b"x" * 40)]))
    data2 = packet([pmsg(to=b"y" * 40)])
    env.put("2.pkt", data2)
    os.chmod(p1, 0)
    r = env.run()
    os.chmod(p1, 0o644)
    assert r.returncode == 1
    assert [l for l in env.loglines("warn") if l[1].startswith("can't read 1.pkt")]
    assert env.get("2.pkt") == reference(data2)[0]
    env.cleanup()


@test
def idempotent():
    env = Env()
    data = packet([pmsg(to=b"x" * 40, frm=b"y" * 99, subj=b"z" * 150)] * 3, tail=b"\0")
    env.put("1.pkt", data)
    env.run()
    first = env.get("1.pkt")
    env.run()
    assert env.get("1.pkt") == first == reference(data)[0]
    warns = [l[1] for l in env.loglines("warn")]
    assert len([w for w in warns if w.startswith("truncated ")]) == 9
    assert len([w for w in warns if "not a packet terminator" in w]) == 2
    assert [l[1] for l in env.loglines("info")] == [
        "processed 1.pkt: 3 messages, 9 fields truncated",
        "processed 1.pkt: 3 messages, nothing truncated"]
    env.cleanup()


@test
def fuzz():
    rnd = random.Random(12345)
    env = Env(cfg="LogLevel warn\n")
    for it in range(1500):
        msgs = []
        for _ in range(rnd.randrange(0, 8)):
            msgs.append(pmsg(
                to=bytes(rnd.randrange(1, 256) for _ in range(rnd.choice([0, 3, 35, 36, 37, 120]))),
                frm=bytes(rnd.randrange(1, 256) for _ in range(rnd.choice([0, 3, 35, 36, 37, 120]))),
                subj=bytes(rnd.randrange(1, 256) for _ in range(rnd.choice([0, 10, 71, 72, 73, 300]))),
                text=bytes(rnd.randrange(1, 256) for _ in range(rnd.randrange(0, 200)))))
        data = bytearray(packet(msgs, tail=rnd.choice([b"\0\0", b"\0", b"", b"xyz"]), seed=it))
        mode = rnd.randrange(4)
        if mode == 1 and data:  # flip random bytes
            for _ in range(rnd.randrange(1, 6)):
                data[rnd.randrange(len(data))] = rnd.choice([0, 1, 2, 0xff, rnd.randrange(256)])
        elif mode == 2 and data:  # cut
            del data[rnd.randrange(len(data)):]
        elif mode == 3:  # pure garbage
            data = bytearray(rnd.randrange(256) for _ in range(rnd.randrange(0, 400)))
        data = bytes(data)
        path = env.put("f.pkt", data)
        if os.path.exists(env.log):
            os.remove(env.log)
        check_packet(env, "f.pkt", data)
        os.remove(path)
    env.cleanup()

# ---------------------------------------------------------------- main


def main():
    global EXE, VERBOSE
    args = sys.argv[1:]
    only = None
    if "-v" in args:
        VERBOSE = True
        args.remove("-v")
    if "-k" in args:
        i = args.index("-k")
        only = args[i + 1]
        del args[i:i + 2]
    EXE = os.path.abspath(args[0])
    failed = 0
    for t in TESTS:
        if only and only not in t.__name__:
            continue
        t0 = time.time()
        try:
            t()
            print("PASS  %s (%.1fs)" % (t.__name__, time.time() - t0))
        except Exception as e:
            failed += 1
            print("FAIL  %s: %r" % (t.__name__, e))
    print("%d failed" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
