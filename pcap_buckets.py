#!/usr/bin/env python3
"""
pcap_buckets.py -- ground-truth bucket extraction from a pcap, by replicating
the switch's exact parse + length-learning + mask + CRC32 pipeline OFFLINE, and
a precision report on how cleanly distinct CIDs map to distinct buckets.

Why not just use tshark's quic.dcid field?
  For SHORT-header (1-RTT) packets, QUIC carries no DCID length on the wire, so
  tshark only fills quic.dcid when its stateful dissector has tracked the whole
  connection. It frequently gives up (CID rotation, capture started mid-stream)
  and returns blank -- so a quic.dcid-based script silently drops the bulk of
  the traffic and undercounts buckets.

What this does instead:
  The DCID is CLEARTEXT on the wire (header protection covers only the packet
  number and payload, never the CID). So we read the raw UDP payload bytes and
  parse the QUIC header ourselves, mirroring p4src/ingress.p4 exactly:

    * Long header  -> DCID length is on the wire; use it. If the packet is a
                      Handshake (long_packet_type == 2), LEARN that length for
                      this 4-tuple (same as learn_len in the data plane).
    * Short header -> RECALL the learned length for this 4-tuple; read that many
                      cleartext DCID bytes (same as recall_len + mask_tbl).
    * Bucket       -> CRC32(dcid right-padded to 20 bytes) & 0x1FFFF.

  Only the FIRST QUIC packet in a (possibly coalesced) datagram is parsed,
  because the switch parser also only sees the first one.

Precision metrics (the point of the tool):
  * COLLISION -- one bucket holding >1 distinct CID. The 17-bit CRC could in
                 principle map two different CIDs to the same bucket; that would
                 make the switch under-count connections. Reported explicitly.
  * SPLIT     -- one CID landing in >1 bucket. Should never happen with stable
                 length learning; if it does, the learned length changed under a
                 live CID (a learning bug). Reported explicitly.
  Perfect separation == (#distinct CIDs == #buckets) and no collisions/splits.

Usage:
    python3 pcap_buckets.py /tmp/sender.pcap
    python3 pcap_buckets.py /tmp/sender.pcap --switch 2749,20951,29723,...   # diff vs switch
"""

import argparse, os, struct, mmap, zlib, sys, multiprocessing
from collections import defaultdict

BUCKET_BITS = 17
PAD_LEN     = 20

def load_switch_buckets(arg):
    """Accept either a path to a switch dump CSV ('bucket,pkts' rows, as written
    by bfrt_python/dump_buckets.py) or a bare comma-separated bucket list.
    Returns {bucket -> count}; count is 0 when only a bare list was given."""
    counts = {}
    if os.path.isfile(arg):
        with open(arg) as f:
            for line in f:
                tok = line.split(",")[0].strip()
                cnt = line.split(",")[1].strip() if "," in line else "0"
                if not tok.lstrip("-").isdigit():
                    continue                                  # header / blank
                counts[int(tok)] = int(cnt) if cnt.lstrip("-").isdigit() else 0
    else:
        if "/" in arg or arg.endswith(".csv"):
            sys.exit("--switch: file not found: %s" % arg)
        for x in arg.split(","):
            x = x.strip()
            if x:
                counts[int(x)] = 0
    return counts

def bucket(dcid_bytes):
    b = (dcid_bytes + b"\x00" * PAD_LEN)[:PAD_LEN]   # right-pad/trunc to 20 (MSB-aligned)
    return zlib.crc32(b) & ((1 << BUCKET_BITS) - 1)

# ---------------------------------------------------------------------------
# Raw-pcap reader.  We used to shell out to tshark and round-trip every payload
# through a hex text string; on a 23G pcap that serialization dominated the
# runtime.  Since we only ever need the 4-tuple + the first ~26 cleartext bytes
# (flags + version + dcid_len + 20-byte DCID), we walk the capture at the raw
# record layer ourselves -- no subprocess, no per-packet stringification, only
# the link/IP/UDP headers and the payload prefix get touched.
#
# Supports classic pcap (us/ns, both endiannesses) and pcapng.  Link types:
# Ethernet (1, incl. 802.1Q/QinQ VLAN tags), raw IPv4 (101/12/14), Linux SLL
# (113).  IPv6 and non-UDP are skipped.
# ---------------------------------------------------------------------------

PREFIX = 32                       # payload bytes we decode (was tshark's [:64] hex)
_LT_ETHER, _LT_RAW, _LT_SLL, _LT_RAW2, _LT_RAW3 = 1, 101, 113, 12, 14

def _udp443_from_ip(buf, off):
    """Given an IPv4 header starting at off, return (src,dst,sport,dport,payload)
    if it's UDP on port 443, else None.  src/dst are packed-int keys (only used
    for per-4-tuple length learning, never displayed)."""
    if off + 20 > len(buf):
        return None
    vihl = buf[off]
    if vihl >> 4 != 4:                       # not IPv4 (IPv6 carries no cleartext-CID parse here)
        return None
    ihl = (vihl & 0x0F) * 4
    if buf[off + 9] != 17:                    # not UDP
        return None
    src = buf[off + 12:off + 16]
    dst = buf[off + 16:off + 20]
    uoff = off + ihl
    if uoff + 8 > len(buf):
        return None
    sport = (buf[uoff] << 8) | buf[uoff + 1]
    dport = (buf[uoff + 2] << 8) | buf[uoff + 3]
    if sport != 443 and dport != 443:
        return None
    poff = uoff + 8
    return src, dst, sport, dport, bytes(buf[poff:poff + PREFIX])

def _parse_frame(buf, off, end, linktype):
    """Locate the IPv4 header inside one link-layer frame [off:end)."""
    if linktype == _LT_ETHER:
        if off + 14 > end:
            return None
        et = (buf[off + 12] << 8) | buf[off + 13]
        l3 = off + 14
        while et in (0x8100, 0x88A8):         # strip one or more VLAN tags
            if l3 + 4 > end:
                return None
            et = (buf[l3 + 2] << 8) | buf[l3 + 3]
            l3 += 4
        if et != 0x0800:                      # not IPv4
            return None
        return _udp443_from_ip(buf, l3)
    if linktype == _LT_SLL:                   # Linux cooked: 16-byte header, proto at +14
        if off + 16 > end:
            return None
        if (buf[off + 14] << 8 | buf[off + 15]) != 0x0800:
            return None
        return _udp443_from_ip(buf, off + 16)
    if linktype in (_LT_RAW, _LT_RAW2, _LT_RAW3):   # raw IP, frame starts at L3
        return _udp443_from_ip(buf, off)
    return None                               # unsupported link type

# --- format detection + work splitting -------------------------------------
# To parallelize, we cut the capture into byte ranges that begin on real record
# boundaries, then hand one range to each worker process.  A single cheap serial
# pass walks the record/block headers (no payload parse, no CRC) to find a
# boundary near each (filesize / njobs) threshold; that index walk is the only
# serial part, so wall-clock scales with cores for the heavy parse+CRC work.
#
# fmt is a pickle-friendly tuple shared with every worker:
#   ("pcap",   endchar, linktype)
#   ("pcapng", endchar, [linktype per interface])   # workers needn't re-scan IDBs

def detect(pcap, njobs):
    """Return (fmt, splits).  splits is a list of byte offsets on record/block
    boundaries; consecutive pairs tile the whole capture into <= njobs ranges."""
    with open(pcap, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            total = len(mm)
            if mm[:4] == b"\x0a\x0d\x0d\x0a":              # pcapng
                if struct.unpack_from("<I", mm, 8)[0] == 0x1A2B3C4D:
                    end = "<"
                elif struct.unpack_from(">I", mm, 8)[0] == 0x1A2B3C4D:
                    end = ">"
                else:
                    sys.exit("pcapng: bad byte-order magic")
                u32 = struct.Struct(end + "I")
                iface_lt, n = [], 0
                splits, target = [0], total / njobs
                nextt = target
                while n + 12 <= total:
                    btype = u32.unpack_from(mm, n)[0]
                    blen = u32.unpack_from(mm, n + 4)[0]
                    if blen < 12 or n + blen > total:
                        break
                    if btype == 0x00000001:                # Interface Description Block
                        iface_lt.append(struct.unpack_from(end + "H", mm, n + 8)[0])
                    if n >= nextt and len(splits) < njobs:
                        splits.append(n); nextt += target
                    n += blen
                splits.append(total)
                return ("pcapng", end, iface_lt), splits
            # classic pcap
            magic = mm[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                end = "<"                                  # little-endian (us / ns)
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                end = ">"                                  # big-endian
            else:
                sys.exit("not a recognized pcap/pcapng magic")
            linktype = struct.unpack_from(end + "I", mm, 20)[0]
            rec = struct.Struct(end + "IIII")
            n = 24
            splits, target = [24], (total - 24) / njobs
            nextt = 24 + target
            while n + 16 <= total:
                incl = rec.unpack_from(mm, n)[2]
                if n + 16 + incl > total:
                    break
                if n >= nextt and len(splits) < njobs:
                    splits.append(n); nextt += target
                n += 16 + incl
            splits.append(total)
            return ("pcap", end, linktype), splits
        finally:
            mm.close()

def _iter_range(pcap, fmt, start, stop):
    """Yield (src,dst,sport,dport,payload_prefix) for records that START in
    [start, stop).  start must be a real boundary (as produced by detect())."""
    with open(pcap, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            total = len(mm)
            if fmt[0] == "pcap":
                end, linktype = fmt[1], fmt[2]
                rec = struct.Struct(end + "IIII")
                n = start
                while n < stop and n + 16 <= total:
                    incl = rec.unpack_from(mm, n)[2]
                    d = n + 16
                    if d + incl > total:
                        break
                    r = _parse_frame(mm, d, d + incl, linktype)
                    if r:
                        yield r
                    n = d + incl
            else:                                          # pcapng
                end, iface_lt = fmt[1], fmt[2]
                u32 = struct.Struct(end + "I")
                n = start
                while n < stop and n + 12 <= total:
                    btype = u32.unpack_from(mm, n)[0]
                    blen = u32.unpack_from(mm, n + 4)[0]
                    if blen < 12 or n + blen > total:
                        break
                    if btype == 0x00000006:                # Enhanced Packet Block
                        iface = u32.unpack_from(mm, n + 8)[0]
                        caplen = u32.unpack_from(mm, n + 20)[0]
                        poff = n + 28
                        if poff + caplen <= n + blen:
                            lt = iface_lt[iface] if iface < len(iface_lt) else _LT_ETHER
                            r = _parse_frame(mm, poff, poff + caplen, lt)
                            if r:
                                yield r
                    elif btype == 0x00000003:              # Simple Packet Block
                        poff = n + 12
                        lt = iface_lt[0] if iface_lt else _LT_ETHER
                        r = _parse_frame(mm, poff, n + blen - 4, lt)
                        if r:
                            yield r
                    n += blen
        finally:
            mm.close()

def rows(pcap):
    """Yield every UDP/443 datagram in file order (serial whole-file walk)."""
    fmt, splits = detect(pcap, 1)
    yield from _iter_range(pcap, fmt, splits[0], splits[-1])

# --- per-packet accumulation (shared by serial and worker paths) ------------

KINDS = {0: "Initial", 1: "0RTT", 2: "Handshake", 3: "Retry"}

def _fold(acc, dcid, kind):
    """Bucket one DCID and update the accumulator structures in place."""
    b = bucket(dcid)
    h = dcid.hex()
    bp, bc, cb, cp, kp = acc
    bp[b] += 1                                # bucket -> packet count
    bc[b].add(h)                              # bucket -> set of distinct CIDs
    cb[h].add(b)                              # CID -> set of buckets it landed in
    cp[h] += 1                                # CID -> packet count
    kp[kind] += 1                             # header kind -> packet count

def _new_acc():
    return (defaultdict(int), defaultdict(set),
            defaultdict(set), defaultdict(int), defaultdict(int))

def _learn_phase(it):
    """Light pass: record the DCID length each connection's Handshake teaches.
    Handshakes are rare (one per connection), so this map is tiny and merging
    every shard's map yields the same global length register the switch holds."""
    learned = {}                              # 4-tuple -> learned DCID length
    for src, dst, sport, dport, pl in it:
        if len(pl) >= 6 and (pl[0] & 0xB0) == 0xA0:   # long header, type 2 (Handshake)
            learned[(src, dst, sport, dport)] = pl[5]
    return learned

def _bucket_phase(it, learned):
    """Heavy pass: bucket every datagram inline, using the *complete* global
    length map.  No deferral -- so this phase parallelizes cleanly."""
    acc = _new_acc()
    skipped = 0
    for src, dst, sport, dport, pl in it:
        if len(pl) < 2:
            skipped += 1
            continue
        first = pl[0]
        if first & 0x80:                      # long header: length is on the wire
            if len(pl) < 6:
                skipped += 1
                continue
            ptype = (first & 0x30) >> 4        # 0=Init 1=0RTT 2=HS 3=Retry
            _fold(acc, pl[6:6 + pl[5]], KINDS.get(ptype, "Long"))
        else:                                  # short header: recall learned length
            L = learned.get((src, dst, sport, dport), 0)
            _fold(acc, pl[1:1 + L], "Short" if L else "Short(unlearned)")
    return acc, skipped

def _learn_worker(args):
    pcap, fmt, start, stop = args
    return _learn_phase(_iter_range(pcap, fmt, start, stop))

def _bucket_worker(args):
    pcap, fmt, start, stop, learned = args
    return _bucket_phase(_iter_range(pcap, fmt, start, stop), learned)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--switch", help="switch buckets to diff against: either a path to "
                                      "switch_buckets.csv (bucket,pkts) or a comma-separated list")
    ap.add_argument("--out", default="pcap_summary.txt",
                    help="archive the result summary to this file")
    ap.add_argument("-j", "--jobs", type=int, default=0,
                    help="worker processes (0 = all CPUs; 1 = serial)")
    args = ap.parse_args()

    njobs = args.jobs if args.jobs > 0 else (os.cpu_count() or 1)
    fmt, splits = detect(args.pcap, njobs)
    ranges = [(args.pcap, fmt, s, e) for s, e in zip(splits, splits[1:]) if e > s]

    # Two phases, each sharded across workers:
    #   1. learn  -- collect every connection's Handshake-taught DCID length
    #   2. bucket -- with the COMPLETE global length map, bucket every datagram
    #                inline (no deferral, so the heavy CRC work parallelizes).
    if njobs == 1 or len(ranges) <= 1:
        njobs = 1
        learned = _learn_phase(_iter_range(args.pcap, fmt, splits[0], splits[-1]))
        parts = [_bucket_phase(_iter_range(args.pcap, fmt, splits[0], splits[-1]), learned)]
    else:
        with multiprocessing.Pool(len(ranges)) as pool:
            learned = {}
            for m in pool.map(_learn_worker, ranges):
                learned.update(m)
            parts = pool.map(_bucket_worker, [r + (learned,) for r in ranges])

    # ---- merge each shard's accumulators ----
    bucket_pkts, bucket_cids, cid_buckets, cid_pkts, kind_pkts = _new_acc()
    skipped = 0
    for (bp, bc, cb, cp, kp), w_skip in parts:
        for b, c in bp.items(): bucket_pkts[b] += c
        for b, s in bc.items(): bucket_cids[b] |= s
        for h, s in cb.items(): cid_buckets[h] |= s
        for h, c in cp.items(): cid_pkts[h] += c
        for k, c in kp.items(): kind_pkts[k] += c
        skipped += w_skip

    # ---- precision analysis ----
    collisions = {b: cs for b, cs in bucket_cids.items() if len(cs) > 1}
    splits     = {h: bs for h, bs in cid_buckets.items() if len(bs) > 1}
    n_cids     = len(cid_buckets)
    n_bucket   = len(bucket_pkts)
    total_pkts = sum(bucket_pkts.values())
    cids_collided = sum(len(cs) for cs in collisions.values())   # connections conflated
    pkts_collided = sum(bucket_pkts[b] for b in collisions)      # packets under one of them
    # accuracy: a perfect classifier gives one distinct bucket per connection, so
    # the fraction of connections that ended up cleanly separated is the share NOT
    # lost to a collision: (connections - conflated + #collision-buckets) / connections.
    separated = n_cids - cids_collided + len(collisions)
    accuracy = (separated / n_cids * 100.0) if n_cids else 100.0

    R = []                                       # report lines (printed and archived)
    def emit(s=""): R.append(s)

    emit("=" * 64)
    emit("P4-QUIC length-aware classifier -- offline pcap result")
    emit("=" * 64)
    emit("capture                    : %s" % os.path.basename(args.pcap))
    emit("QUIC/443 packets analyzed  : %d  (%d non-parseable skipped)" % (total_pkts, skipped))
    emit("distinct connections (CIDs): %d" % n_cids)
    emit("distinct buckets occupied  : %d" % n_bucket)
    emit("")
    emit("packets by QUIC header kind:")
    for k in sorted(kind_pkts, key=lambda x: -kind_pkts[x]):
        emit("    %-18s %12d" % (k, kind_pkts[k]))
    emit("")
    emit("-" * 64)
    if not collisions and not splits:
        emit("RESULT: CLEAN SEPARATION")
        emit("  %d connections map 1:1 to %d distinct buckets." % (n_cids, n_bucket))
        emit("  No collisions, no splits -- classification accuracy 100.0%.")
    else:
        emit("RESULT: %d COLLISION(S), %d SPLIT(S)" % (len(collisions), len(splits)))
        emit("  classification accuracy : %.2f%%  (%d of %d connections "
             "cleanly separated)" % (accuracy, separated, n_cids))
        if collisions:
            emit("  collisions conflate %d connections into %d buckets "
                 "(%d packets affected) -- the switch UNDER-counts these."
                 % (cids_collided, len(collisions), pkts_collided))
        if splits:
            emit("  %d connections each landed in >1 bucket -- length learning "
                 "was unstable." % len(splits))
    emit("-" * 64)

    if splits:
        emit("")
        emit("splits (connection CID -> buckets it was scattered across):")
        for h, bs in sorted(splits.items(), key=lambda kv: -cid_pkts[kv[0]]):
            emit("    %s : %d pkts -> buckets %s" % (h, cid_pkts[h], sorted(bs)))

    if args.switch:
        sw_counts = load_switch_buckets(args.switch)
        sw, pc = set(sw_counts), set(bucket_pkts)
        both = sw & pc
        sw_only, pc_only = sw - both, pc - both
        emit("")
        emit("-" * 64)
        emit("cross-check vs switch (%s):" % os.path.basename(args.switch))
        emit("    switch buckets : %d" % len(sw))
        emit("    pcap buckets   : %d" % len(pc))
        emit("    agree (both)   : %d" % len(both))
        emit("    switch only    : %d   <- buckets the offline model did NOT reproduce"
             % len(sw_only))
        emit("    pcap only      : %d" % len(pc_only))
        # switch-only buckets are the actionable diagnostic; list them with the
        # switch's packet count (high-volume = a real mismatch, not a straggler).
        if sw_only:
            top = sorted(sw_only, key=lambda b: -sw_counts.get(b, 0))[:20]
            emit("    switch-only (bucket:pkts): %s%s"
                 % (", ".join("%d:%d" % (b, sw_counts[b]) for b in top),
                    " ..." if len(sw_only) > 20 else ""))

    text = "\n".join(R)
    print(text)
    with open(args.out, "w") as f:
        f.write(text + "\n")
    print("\n(summary archived to %s)" % args.out)

if __name__ == "__main__":
    main()
