"""Minimal DNS wire-format helpers: parse a question, build answers, read record TTLs.
Enough for a forwarding resolver with a sinkhole; no dependency."""
import random
import struct

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_OPT = 41
TYPE_HTTPS = 65
TYPE_ANY = 255

TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
              33: "SRV", 41: "OPT", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

RCODE_OK = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5


class DnsError(Exception):
    pass


def parse_name(buf, off, depth=0):
    """Decode a (possibly compressed) name at offset. Returns (name, offset after it)."""
    if depth > 20:
        raise DnsError("compression loop")
    labels = []
    while True:
        if off >= len(buf):
            raise DnsError("truncated name")
        length = buf[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise DnsError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if ptr >= off:
                raise DnsError("forward pointer")
            rest, _ = parse_name(buf, ptr, depth + 1)
            if rest:
                labels.append(rest)
            off += 2
            break
        off += 1
        labels.append(buf[off:off + length].decode("ascii", "replace"))
        off += length
    return ".".join(l for l in labels if l), off


def parse_question(buf):
    """Return (qname, qtype, qclass, offset after the question) of the first question."""
    if len(buf) < 12:
        raise DnsError("short packet")
    qdcount = struct.unpack("!H", buf[4:6])[0]
    if qdcount < 1:
        raise DnsError("no question")
    name, off = parse_name(buf, 12)
    if off + 4 > len(buf):
        raise DnsError("truncated question")
    qtype, qclass = struct.unpack("!HH", buf[off:off + 4])
    return name, qtype, qclass, off + 4


def encode_name(name):
    out = b""
    for label in name.strip(".").split("."):
        if not label:
            continue
        raw = label.encode("ascii") if label.isascii() else label.encode("idna")
        if len(raw) > 63:
            raise DnsError("label too long")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, qtype, qclass=1, qid=None, rd=True):
    qid = random.randint(0, 65535) if qid is None else qid
    flags = 0x0100 if rd else 0
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", qtype, qclass)


def build_response(query, rcode=RCODE_OK, answers=(), ttl=60):
    """Answer the given query. answers = [(rtype, rdata bytes)], owner = the question name."""
    name, qtype, qclass, qend = parse_question(query)
    rd = (query[2] & 0x01)
    flags = 0x8000 | (rd << 8) | 0x0080 | (rcode & 0xF)
    out = query[:2] + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0) + query[12:qend]
    for rtype, rdata in answers:
        out += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return out


def parse_records(buf):
    """Return (header dict, records). Record = (name, rtype, rclass, ttl, rdata_offset, rdlen, section)
    with section 0 = answer, 1 = authority, 2 = additional."""
    if len(buf) < 12:
        raise DnsError("short packet")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _, off = parse_name(buf, off)
        off += 4
    recs = []
    for section, count in ((0, an), (1, ns), (2, ar)):
        for _ in range(count):
            name, off = parse_name(buf, off)
            if off + 10 > len(buf):
                raise DnsError("truncated record")
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
            off += 10
            recs.append((name, rtype, rclass, ttl, off, rdlen, section))
            off += rdlen
    hdr = {"id": qid, "flags": flags, "rcode": flags & 0xF, "tc": bool(flags & 0x0200),
           "qd": qd, "an": an, "ns": ns, "ar": ar}
    return hdr, recs


def response_ttl(buf, default=30, floor=5, cap=300):
    """Cache lifetime for a response: the smallest answer TTL (authority when no answer)."""
    try:
        hdr, recs = parse_records(buf)
    except DnsError:
        return default
    ttls = [r[3] for r in recs if r[6] == 0 and r[1] != TYPE_OPT]
    if not ttls:
        ttls = [r[3] for r in recs if r[6] == 1]
    if not ttls:
        return default
    return max(floor, min(cap, min(ttls)))


def rcode_of(buf):
    return buf[3] & 0xF if len(buf) >= 4 else RCODE_SERVFAIL


def is_truncated(buf):
    return len(buf) >= 4 and bool(buf[2] & 0x02)


def is_response(buf):
    return len(buf) >= 3 and bool(buf[2] & 0x80)
