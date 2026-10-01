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


def pkt_addr(h):
    """Independent model: "orig -> dest" from a packet header."""
    def w(o):
        return h[o] | h[o + 1] << 8

    def s(o):  # parts of addresses are signed
        return struct.unpack_from("<h", h, o)[0]
    oz, dz, onet, dnet, op, dp = s(34), s(36), s(20), s(22), 0, 0
    cw, cwc = w(44), w(40)
    if cw & 1 and cw == ((cwc & 0xff) << 8 | cwc >> 8):
        if w(46):
            oz, dz = s(46), s(48)
        op, dp = s(50), s(52)
        if op and onet == -1:
            onet = s(38)
    elif w(16) == 2:
        op, dp = s(4), s(6)

    def fmt(z, n, f, p):
        return ("%d:" % z if z else "") + "%d/%d" % (n, f) + (".%d" % p if p else "")
    return "%s -> %s" % (fmt(oz, onet, s(0), op), fmt(dz, dnet, s(2), dp))


def clean(b):
    return "".join("?" if c < 32 or c == 127 else chr(c) for c in b)


def msg_info(mh, to, frm, subj, text):
    """Independent model: the message in a modified message log line."""
    onode, dnode, onet, dnet = struct.unpack("<hhhh", mh[2:10])
    line = text[:255].split(b"\r")[0]
    echo = line.startswith(b"AREA:")
    return 'area %s, from %s (%d/%d) to %s%s, subject "%s"' % (
        (clean(line[5:]) or "<empty>") if echo else "NETMAIL", clean(frm[:35]), onet, onode,
        clean(to[:35]), "" if echo else " (%d/%d)" % (dnet, dnode), clean(subj[:71]))


def reference(data):
    """Independent model: returns (output, msgs, [(msg, field, len)], tail,
    {msg: info}).

    msgs counts a message cut off by the end of the file too; tail is the
    offset of the data after the last complete message; info is the
    message in the modified message log lines."""
    if len(data) < 58:
        return data, 0, [], len(data), {}
    out = bytearray(data[:58])
    p, n, tr, info = 58, 0, [], {}
    while data[p:p + 2] == b"\x02\x00":
        n += 1
        if len(data) - p < 34:
            break
        q = p + 34
        out += data[p:q]
        fields = [b""] * 4
        for i in range(4):
            z = data.find(b"\0", q)
            f = data[q:z] if z >= 0 else data[q:]
            fields[i] = f
            if z < 0:
                out += f
                break
            if i < 3 and len(f) > LIMITS[i] - 1:
                tr.append((n, i, len(f)))
                f = f[:LIMITS[i] - 1]
            out += f + b"\0"
            q = z + 1
        if tr and tr[-1][0] == n:
            info[n] = msg_info(data[p:p + 34], *fields)
        if z < 0:
            return bytes(out), n, tr, p, info
        p = q
    out += data[p:]
    return bytes(out), n, tr, p, info


def expected_problem(data):
    """None for a proper packet, else ("err" | "warn", start of message)."""
    _, n, _, tail, _ = reference(data)
    rest = data[tail:]
    if len(data) < 58:
        return ("err", "%s is not a packet: only %d bytes" % ("{0}", len(data)))
    if rest == b"\0\0":
        return None
    if n == 0:
        return ("err", "{0} is not a packet: no packed messages after the packet "
                "header (%d bytes of unknown data at offset %d), skipped" % (len(rest), tail))
    if rest[:2] == b"\x02\x00":
        return ("warn", "{0}: message #%d (offset %d) is cut off by the end of the "
                "file, its unterminated part is kept as is" % (n, tail))
    if rest == b"":
        return ("warn", "{0}: no packet terminator, the file ends right after "
                "message #%d" % n)
    if rest == b"\0":
        return ("warn", "{0}: incomplete packet terminator after message #%d "
                "(1 byte at offset %d), kept as is" % (n, tail))
    if rest[:2] == b"\0\0":
        return ("warn", "{0}: %d bytes of unknown data after the packet terminator "
                "(offset %d), kept as is" % (len(rest) - 2, tail + 2))
    return ("warn", "{0}: unknown data instead of a packet terminator after "
            "message #%d (%d bytes at offset %d), kept as is without parsing"
            % (n, len(rest), tail))


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

    def run(self, args=None, cwd=None, cfg=True, dirs=None):
        """Runs pktsan on dirs (default: the packet directory) from cwd
        (default: its parent, so the current directory is not used)."""
        cmd = [EXE] + (["-c", self.cfg] if cfg else []) + (args or []) + \
            ([self.dir] if dirs is None else dirs)
        r = subprocess.run(cmd, cwd=cwd or self.root, capture_output=True)
        if VERBOSE:
            print("   ", cmd, r.returncode, r.stdout, r.stderr)
        if b"Sanitizer" in r.stderr or b"runtime error" in r.stderr:
            raise AssertionError("sanitizer: " + r.stderr.decode(errors="replace"))
        return r

    def logtext(self):
        if not os.path.exists(self.log):
            return ""
        with open(self.log, encoding="latin-1", newline="") as f:
            return f.read()

    def logsplit(self):
        return self.logtext().split("\n")[:-1]

    def loglines(self, level=None, dirs=False):
        """Log lines as (level, text); "processing directory" lines only if dirs.

        Every file name must be logged with the full path of the directory,
        which is then removed from the text."""
        prefix = self.dir + "/"
        res = []
        for line in self.logsplit():
            m = re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \[(\w+)\] (.*)$", line)
            assert m, "bad log line: %r" % line
            text = m.group(2)
            # a modified message line starts with the packet name only
            ismsg = re.match(r"[^\s/]*\.pkt: msg \d+, area ", text, re.I)
            for f in re.findall(r"[^\s(]+\.(?:pkt|pk\$|pk#)", text[ismsg.end() if ismsg else 0:],
                                re.I):
                assert f.startswith(self.root + "/"), "no full path: %r" % line
            text = text.replace(prefix, "")
            text = re.sub(r"(\.pkt) \([^()]* -> [^()]*\)", r"\1", text, flags=re.I)
            isdir = text.startswith("processing directory ")
            assert (m.group(1) == "info") == (isdir or text.startswith("processed ")), line
            if isdir and not dirs:
                continue
            if level is None or m.group(1) == level:
                res.append((m.group(1), text))
        return res

    def files(self):
        return sorted(os.listdir(self.dir))

    def cleanup(self):
        for d, _, _ in os.walk(self.root):
            os.chmod(d, 0o755)
        shutil.rmtree(self.root)


def is_msg_line(text):
    return re.match(r"[^\s/]*\.pkt: msg \d+, area ", text, re.I) is not None


def msg_lines(tr, info, name):
    """Independent model: the modified message log lines."""
    fields = {}
    for m, f, ln in tr:
        fields.setdefault(m, []).append("%s %d -> %d" % (NAMES[f], ln, LIMITS[f] - 1))
    return ["%s: msg %d, %s: truncating %s" % (os.path.basename(name), m, info[m], ", ".join(fs))
            for m, fs in fields.items()]


def check_packet(env, name, data, r=None):
    """Process one packet and compare with the reference model."""
    path = env.put(name, data)
    ino = os.stat(path).st_ino
    if r is None:
        r = env.run()
    prob = expected_problem(data)
    skipped = prob is not None and prob[0] == "err"
    assert r.returncode == (1 if skipped else 0), r
    exp, n, tr, _, info = reference(data)
    got = env.get(name)
    if skipped:
        assert got == data and tr == []
    assert got == exp, "output differs from reference"
    st = os.stat(path)
    assert st.st_mtime == 1000000000, "mtime not preserved"
    if not tr:
        assert st.st_ino == ino, "unchanged packet was rewritten"
    lines = env.loglines()
    mod = len(set(m for m, _, _ in tr))
    texts = [l[1] for l in lines]
    # the packet, then its modified messages, all together
    block = (["modifying %s" % name] + msg_lines(tr, info, name)) if tr else []
    mods = [l for l in lines if is_msg_line(l[1]) or l[1].startswith("modifying ")]
    assert mods == [("warn", t) for t in block], (mods, block)
    if block:
        i = texts.index(block[0])
        assert texts[i:i + len(block)] == block, texts
    processed = [l for l in lines if l[1].startswith("processed ")]
    other = [l for l in lines if l not in processed and l not in mods]
    if prob is None:
        assert other == [], other
    else:
        assert len(other) == 1 and other[0][0] == prob[0] and \
            other[0][1].startswith(prob[1].format(name)), (other, prob)
    if skipped:
        assert processed == []
    elif "LogLevel info" in open(env.cfg).read():
        assert processed == [("info", "processed %s: messages %d, modified %d" % (
            name, n, mod))], processed
    assert not [f for f in env.files() if f.lower().endswith((".pk$", ".pk#"))], env.files()
    # the addresses follow the packet name wherever the header was read
    full = os.path.join(env.dir, name)
    for line in env.logsplit():
        if full in line:
            if len(data) >= 58:
                assert "%s (%s)" % (full, pkt_addr(data)) in line, line
            else:
                assert full + " (" not in line, line
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
    assert env.loglines() == [("info", "processed 0001.pkt: messages 2, modified 0")]
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
    assert env.loglines() == [
        ("warn", "modifying ab.pkt"),
        ("warn", "ab.pkt: msg 2, area NETMAIL, from %s (5020/1) to %s (5030/2), subject \"%s\": "
         "truncating toUserName 40 -> 35, fromUserName 36 -> 35, subject 200 -> 71"
         % ("F" * 35, "T" * 35, "S" * 71)),
        ("info", "processed ab.pkt: messages 2, modified 1")]
    env.cleanup()


@test
def message_info():
    S = b"S" * 80
    cases = [
        (b"AREA:RU.TEST\rtext\r", "RU.TEST"),
        (b"\x01AREA:RU.TEST\r", "NETMAIL"),
        (b"AREA:RU.TEST\nx\r", "RU.TEST?x"),
        (b"AREA:R50", "R50"),
        (b"AREA:\rtext\r", "<empty>"),
        (b"AREA:", "<empty>"),
        (b"AREA:A\x01B\x7f\r", "A?B?"),
        (b"AREA:" + b"x" * 300, "x" * 250),
        (b"\x01MSGID: 2:5020/1 1\rAREA:R50\r", "NETMAIL"),
        (b"text\r", "NETMAIL"),
        (b"", "NETMAIL"),
    ]
    for text, area in cases:
        env = Env()
        data = packet([pmsg(subj=S, text=text)])
        to = "All" if area != "NETMAIL" else "All (5030/2)"
        info = 'area %s, from Sysop (5020/1) to %s, subject "%s"' % (area, to, "S" * 71)
        assert reference(data)[4] == {1: info}, (text, reference(data)[4], info)
        check_packet(env, "m.pkt", data)
        assert env.loglines("warn")[1:] == [
            ("warn", "m.pkt: msg 1, %s: truncating subject 80 -> 71" % info)], env.logtext()
        env.cleanup()
    # strings as written, addresses from the message header
    for subj, shown in ((b"", ""), (b"x" * 71, "x" * 71), (b"a\rb", "a?b")):
        env = Env()
        hdr = struct.pack("<HHHHHHH", 2, 11, 22, 33, 44, 0, 0)
        check_packet(env, "m.pkt", packet([pmsg(to=b"T" * 50, frm=b"A\tB\xa0\x85",
                                                subj=subj, hdr=hdr)]))
        assert env.loglines("warn")[1:] == [
            ("warn", 'm.pkt: msg 1, area NETMAIL, from A?B\xa0\x85 (33/11) to %s (44/22), '
             'subject "%s": truncating toUserName 50 -> 35' % ("T" * 35, shown))], env.logtext()
        env.cleanup()
    # nets and nodes are signed: -1 in requests for an address
    env = Env()
    hdr = struct.pack("<HhhhhHH", 2, -1, -2, 5020, -32768, 0, 0)
    check_packet(env, "m.pkt", packet([pmsg(to=b"T" * 50, hdr=hdr)]))
    assert env.loglines("warn")[1:] == [
        ("warn", 'm.pkt: msg 1, area NETMAIL, from Sysop (5020/-1) to %s (-32768/-2), '
         'subject "Hello": truncating toUserName 50 -> 35' % ("T" * 35))], env.logtext()
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
def streaming_memory():
    """A packet bigger than the memory limit is processed."""
    if "asan" in os.path.basename(EXE):
        return
    import resource
    env = Env()
    text = b"x" * (100 * 1024 * 1024)
    data = packet([pmsg(subj=b"S" * 100, text=text), pmsg(to=b"T" * 40)])
    env.put("big.pkt", data)
    lim = 64 * 1024 * 1024
    r = subprocess.run([EXE, "-c", env.cfg, env.dir], cwd=env.root, capture_output=True,
                       preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS, (lim, lim)))
    assert r.returncode == 0, r
    assert env.get("big.pkt") == reference(data)[0]
    assert [l[1] for l in env.loglines("info")] == [
        "processed big.pkt: messages 2, modified 2"]
    env.cleanup()


def header(onode=100, dnode=200, onet=5001, dnet=5030, oz=0, dz=0,
           qoz=0, qdz=0, op=0, dp=0, aux=0, cw=False, sub=0, p22=(0, 0)):
    """A packet header: type 2+ with cw, type 2.2 with sub=2, else type 2."""
    h = bytearray(58)
    struct.pack_into("<HH", h, 0, onode, dnode)
    struct.pack_into("<HH", h, 4, *p22)
    struct.pack_into("<HH", h, 16, sub, 2)
    struct.pack_into("<HH", h, 20, onet, dnet)
    struct.pack_into("<HH", h, 34, qoz, qdz)
    if cw:
        struct.pack_into("<HH", h, 38, aux, 0x0100)   # AuxNet, CW copy
        struct.pack_into("<H", h, 44, 0x0001)         # CW: type 2+
        struct.pack_into("<HHHH", h, 46, oz, dz, op, dp)
    return bytes(h)


@test
def addresses():
    cases = [
        # type 2, zones from QMail fields, no zones
        (header(qoz=2, qdz=2), "2:5001/100 -> 2:5030/200"),
        (header(), "5001/100 -> 5030/200"),
        # type 2+: points, point with net 0xFFFF and AuxNet, point 0
        (header(cw=True, oz=2, dz=2, op=1), "2:5001/100.1 -> 2:5030/200"),
        (header(cw=True, oz=2, dz=2, onet=0xffff, aux=50, op=4, dp=7),
         "2:50/100.4 -> 2:5030/200.7"),
        (header(cw=True, oz=2, dz=1, qoz=3, qdz=3), "2:5001/100 -> 1:5030/200"),
        (header(cw=True, qoz=2, qdz=2, dp=3), "2:5001/100 -> 2:5030/200.3"),
        # type 2.2
        (header(sub=2, qoz=2, qdz=2, p22=(5, 0)), "2:5001/100.5 -> 2:5030/200"),
        # parts of addresses are signed
        (header(qoz=2, qdz=2, onode=0xffff, dnet=0x8000), "2:5001/-1 -> 2:-32768/200"),
        (header(cw=True, oz=2, dz=2, onet=0xffff, aux=0xfffe, op=4, dnode=0xffff),
         "2:-2/100.4 -> 2:5030/-1"),
        (header(cw=True, oz=0xffff, dz=2, op=0xfffe, dp=0x8000),
         "-1:5001/100.-2 -> 2:5030/200.-32768"),
        (header(qoz=0xfffd, qdz=2, sub=2, p22=(0xffff, 3)), "-3:5001/100.-1 -> 2:5030/200.3"),
    ]
    for h, addr in cases:
        assert pkt_addr(h) == addr, (pkt_addr(h), addr)
        env = Env()
        data = h + pmsg(subj=b"S" * 80) + b"\0\0"
        check_packet(env, "a.pkt", data)
        assert ("processed %s/a.pkt (%s): messages 1, modified 1" % (env.dir, addr)
                in env.logtext()), env.logtext()
        env.cleanup()


@test
def terminators():
    long = pmsg(to=b"L" * 50)
    for tail in (b"\0\0", b"\0", b"", b"\0\0\0\0", b"\0\0garbage",
                 b"\x01\x00junk", b"\x02", b"\x00\x01", b"\xff"):
        env = Env()
        n, tr = check_packet(env, "t.pkt", packet([pmsg(), long], tail=tail))
        assert n == 2 and tr == [(2, 0, 50)], tail
        env.cleanup()


@test
def incomplete_last_message():
    base = packet([pmsg(frm=b"F" * 60)], tail=b"")
    last = pmsg(to=b"T" * 80, frm=b"F" * 80, subj=b"S" * 80, text=b"text")
    for cut in range(2, len(last)):
        env = Env()
        n, tr = check_packet(env, "i.pkt", base + last[:cut])
        # complete strings of a cut off message are truncated too
        done = [i for i, end in enumerate((34 + 81, 34 + 162, 34 + 243)) if cut >= end]
        assert n == 2 and tr == [(1, 1, 60)] + [(2, i, 80) for i in done], cut
        env.cleanup()
    # the only message of a packet is cut off
    env = Env()
    n, tr = check_packet(env, "i.pkt", pkt_header() + pmsg(subj=b"S" * 80)[:-1])
    assert n == 1 and tr == [(1, 2, 80)]
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
    full = packet([pmsg(to=b"Z" * 50)])
    for size in (0, 1, 2, 57, 58, 59, 60, 91, 92, 92 + 50, 92 + 51):
        env = Env()
        n, tr = check_packet(env, "s.pkt", full[:size])
        assert tr == ([(1, 0, 50)] if size == 92 + 51 else [])
        if size < 58:
            assert env.loglines() == [("err", "s.pkt is not a packet: only %d bytes, "
                                       "shorter than a packet header, skipped" % size)]
        elif size < 60:
            assert env.loglines()[0][0] == "err", size
        else:
            assert env.loglines()[2 if tr else 0] == ("warn", "s.pkt: message #1 (offset 58) is cut "
                                         "off by the end of the file, its unterminated "
                                         "part is kept as is"), size
        env.cleanup()
    # a valid empty packet is fine
    env = Env()
    check_packet(env, "s.pkt", packet([]))
    assert env.loglines() == [("info", "processed s.pkt: messages 0, modified 0")]
    env.cleanup()
    # garbage right after the header
    env = Env()
    check_packet(env, "s.pkt", packet([], tail=b"\x01\x00" + b"x" * 100))
    assert env.loglines() == [("err", "s.pkt is not a packet: no packed messages after "
                               "the packet header (102 bytes of unknown data at offset "
                               "58), skipped")]
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
    assert len([l for l in env.loglines("warn") if is_msg_line(l[1])]) == 5
    env.cleanup()


@test
def log_level_warn():
    env = Env(cfg="LogLevel warn\n")
    env.put("1.pkt", packet([pmsg()]))
    env.put("2.pkt", packet([pmsg(to=b"x" * 36)]))
    env.put("3.pkt", packet([pmsg()], tail=b"\0"))
    assert env.run().returncode == 0
    # packets are processed in directory order
    assert sorted(env.loglines()) == [
        ("warn", "2.pkt: msg 1, area NETMAIL, from Sysop (5020/1) to %s (5030/2), subject \"Hello\": "
         "truncating toUserName 36 -> 35" % ("x" * 35)),
        ("warn", "3.pkt: incomplete packet terminator after message #1 (1 byte at offset %d), kept as is" % (58 + len(pmsg()))),
        ("warn", "modifying 2.pkt")]
    env.cleanup()


@test
def log_level_info_lists_all_packets():
    env = Env()
    for i in range(5):
        env.put("%d.pkt" % i, packet([pmsg(subj=b"s" * (70 + i))]))
    assert env.run().returncode == 0
    lines = env.loglines()
    assert len([l for l in lines if l[1].startswith("processed ")]) == 5
    assert len([l for l in lines if is_msg_line(l[1])]) == 3
    env.cleanup()


@test
def directory_line():
    env = Env()
    env.put("1.pkt", packet([pmsg()]))
    assert env.run().returncode == 0
    assert env.loglines(dirs=True) == [
        ("info", "processing directory %s" % env.dir),
        ("info", "processed 1.pkt: messages 1, modified 0")]
    # logged even when there is nothing to process
    os.remove(os.path.join(env.dir, "1.pkt"))
    os.remove(env.log)
    assert env.run().returncode == 0
    assert env.loglines(dirs=True) == [
        ("info", "processing directory %s" % env.dir)]
    env.cleanup()
    # not logged at the warn level
    env = Env(cfg="LogLevel warn\n")
    env.put("1.pkt", packet([pmsg()]))
    assert env.run().returncode == 0
    assert env.logtext() == ""
    env.cleanup()


@test
def several_directories():
    env = Env()
    env.put("1.pkt", packet([pmsg(to=b"x" * 40)]))
    other = os.path.join(env.root, "other")
    os.mkdir(other)
    with open(os.path.join(other, "2.pkt"), "wb") as f:
        f.write(packet([pmsg(subj=b"s" * 80)]))
    missing = os.path.join(env.root, "missing")
    # a missing directory is an error, the others are processed
    r = env.run(dirs=[env.dir, missing, other])
    assert r.returncode == 1, r
    lines = [l for l in env.loglines(dirs=True) if l[0] != "warn"]
    assert lines == [
        ("info", "processing directory %s" % env.dir),
        ("info", "processed 1.pkt: messages 1, modified 1"),
        ("info", "processing directory %s" % missing),
        ("err", "can't read directory %s: No such file or directory" % missing),
        ("info", "processing directory %s" % other),
        ("info", "processed %s/2.pkt: messages 1, modified 1" % other)]
    with open(os.path.join(other, "2.pkt"), "rb") as f:
        assert f.read() == reference(packet([pmsg(subj=b"s" * 80)]))[0]
    env.cleanup()


@test
def relative_directory():
    """The directory is used and logged as given."""
    env = Env()
    env.put("1.pkt", packet([pmsg(to=b"x" * 40)]))
    for d, cwd in (("in", env.root), ("in/", env.root), (".", env.dir)):
        if os.path.exists(env.log):
            os.remove(env.log)
        assert env.run(dirs=[d], cwd=cwd).returncode == 0
        text = env.logtext()
        assert "processing directory %s\n" % d in text, (d, text)
        assert "processed %s (" % os.path.join(d, "1.pkt") in text, (d, text)
    assert env.get("1.pkt") == reference(packet([pmsg(to=b"x" * 40)]))[0]
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
    r = subprocess.run([EXE, "-c", env.cfg + ".none", env.dir], cwd=env.dir, capture_output=True)
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
    assert "[warn] 1.pkt: msg 1, area NETMAIL, " in text and "[info]" not in text
    env.cleanup()


@test
def relative_log_path():
    env = Env(with_log=False)
    with open(env.cfg, "a") as f:
        f.write("LogFile rel.log\n")
    env.put("1.pkt", packet([pmsg()]))
    # config given by an absolute and by a relative path
    for cfg in (env.cfg, os.path.join("..", os.path.basename(env.cfg))):
        r = subprocess.run([EXE, "-c", cfg, env.dir], cwd=env.dir, capture_output=True)
        assert r.returncode == 0 and r.stdout == b"", r
    assert env.files() == ["1.pkt"]
    with open(os.path.join(env.root, "rel.log")) as f:
        assert f.read().count("processed ") == 2
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
    r = subprocess.run([exe, "."], cwd=env.dir, capture_output=True)
    assert r.returncode == 0 and r.stdout == b"", r
    assert "processed ./1.pkt" in env.logtext()
    # started by a relative path: the config is still next to the program
    os.remove(env.log)
    r = subprocess.run([os.path.join("..", "bin", "pktsan"), "."], cwd=env.dir, capture_output=True)
    assert r.returncode == 0 and r.stdout == b"", r
    assert "processed ./1.pkt" in env.logtext()
    # started without a path (found in PATH): the config is looked for
    # in the current directory
    r = subprocess.run(["pktsan", "."], cwd=env.dir, capture_output=True,
                       env=dict(os.environ, PATH=bindir))
    assert r.returncode == 0 and b"processed ./1.pkt (" in r.stdout, r
    # no config at all: defaults, log to stdout
    os.remove(os.path.join(bindir, "pktsan.cfg"))
    r = subprocess.run([exe, "."], cwd=env.dir, capture_output=True)
    assert r.returncode == 0 and re.search(
        rb"\[info\] processed \./1\.pkt \([^)]*\): messages 1, modified 0", r.stdout), r
    env.cleanup()


@test
def arguments_rejected():
    env = Env()
    data = packet([pmsg(to=b"x" * 40)])
    env.put("1.pkt", data)
    # no directories: help on stderr
    for args in ([], ["-c", env.cfg]):
        r = subprocess.run([EXE] + args, cwd=env.dir, capture_output=True)
        assert r.returncode == 1 and b"Usage: pktsan [-c config] dir..." in r.stderr, (args, r)
        assert r.stdout == b"", r
    # bad options: getopt's message
    for args in (["-x", env.dir], ["-c"]):
        r = subprocess.run([EXE] + args, cwd=env.dir, capture_output=True)
        assert r.returncode == 1 and r.stderr and b"Usage" not in r.stderr, (args, r)
    assert env.get("1.pkt") == data and env.logtext() == ""
    # help
    r = subprocess.run([EXE, "-h", env.dir], cwd=env.dir, capture_output=True)
    assert r.returncode == 0 and b"Usage: pktsan [-c config] dir..." in r.stdout, r
    assert env.get("1.pkt") == data and env.logtext() == ""
    env.cleanup()


@test
def temp_files_from_interrupted_run():
    env = Env()
    data = packet([pmsg(to=b"x" * 40)])
    env.put("1.pkt", data)
    env.put("1.pk$", b"incomplete")      # write was interrupted: delete
    env.put("2.PKT", packet([pmsg()]))
    env.put("2.PK#", b"incomplete")
    env.put("3.pk$", data)               # interrupted after delete: restore
    env.put("4.PK#", data)               # in the same case
    env.put("5.pK$", data)
    env.put("6.Pk#", data)
    assert env.run().returncode == 0
    assert env.files() == ["1.pkt", "2.PKT", "3.pkt", "4.PKT", "5.pKt", "6.PkT"], env.files()
    assert env.get("1.pkt") == env.get("3.pkt") == env.get("4.PKT") == env.get("5.pKt") == \
        env.get("6.PkT") == reference(data)[0]
    assert sorted(l for l in env.loglines("warn") if "temporary" in l[1]) == [
        ("warn", "deleted incomplete temporary file 1.pk$"),
        ("warn", "deleted incomplete temporary file 2.PK#"),
        ("warn", "restored 3.pkt from temporary file 3.pk$"),
        ("warn", "restored 4.PKT from temporary file 4.PK#"),
        ("warn", "restored 5.pKt from temporary file 5.pK$"),
        ("warn", "restored 6.PkT from temporary file 6.Pk#")]
    assert ("info", "processed 3.pkt: messages 1, modified 1") in env.loglines()
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
    assert [l for l in env.loglines() if l[0] != "info"] == [
        ("warn", "modifying 1.pkt"),
        ("warn", "1.pkt: msg 1, area NETMAIL, from Sysop (5020/1) to %s (5030/2), subject "
         "\"Hello\": truncating toUserName 40 -> 35" % ("x" * 35)),
        ("err", "can't write 1.pk$: Permission denied, 1.pkt skipped")]
    assert [l[1] for l in env.loglines("info")] == ["processed 2.pkt: messages 1, modified 0"]
    env.cleanup()


@test
def broken_symlink_is_logged():
    env = Env()
    os.symlink("nowhere", os.path.join(env.dir, "1.pkt"))
    r = env.run()
    assert r.returncode == 1
    assert env.loglines() == [
        ("err", "can't stat 1.pkt: No such file or directory, skipped")], env.logtext()
    assert "can't stat %s/1.pkt:" % env.dir in env.logtext()
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
    assert [l for l in env.loglines("err") if l[1].startswith("can't read 1.pkt")]
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
    assert len([w for w in warns if is_msg_line(w)]) == 3
    assert len([w for w in warns if "incomplete packet terminator" in w]) == 2
    assert [l for l in env.loglines() if l[1].startswith("processed ")] == [
        ("info", "processed 1.pkt: messages 3, modified 3"),
        ("info", "processed 1.pkt: messages 3, modified 0")]
    env.cleanup()


@test
def fuzz():
    rnd = random.Random(12345)
    env = Env()
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
