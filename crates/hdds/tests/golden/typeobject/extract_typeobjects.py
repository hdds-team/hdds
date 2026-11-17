#!/usr/bin/env python3
"""Extract every TypeObject (minimal and complete) from Cyclone idlc output.

Usage: extract_typeobjects.py typeobject_corpus.c > cyclone-0.11-typeobjects.txt
Output lines: <name> <M|C> <hash14 hex> <TypeObject hex>
where the TypeObject is the serialized outer TypeObject union (DHEADER,
EK octet, the inner Minimal/CompleteTypeObject), which is exactly the MD5
preimage of the hash (checked: a mismatch aborts).
Names: a complete object carries its own name; a minimal object is named by
TYPE_INFO_CDR (topic types) or by walking the member type identifiers of a
named minimal/complete pair in parallel (dependent types)."""
import hashlib, re, sys

src = open(sys.argv[1]).read()

def u32(b, p): return int.from_bytes(b[p:p+4], 'little')
def u16(b, p): return int.from_bytes(b[p:p+2], 'little')
def al(p, n): return (p + n - 1) & ~(n - 1)

objs = {}  # hash hex -> (kind, bytes)
for name, body in re.findall(r'#define TYPE_MAP_CDR_(\w+) \(const unsigned char \[\]\)\{ \\\n(.*?)\}', src, re.S):
    b = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-f]{2})', body))
    pos = 0
    for want in (0xf1, 0xf2):
        pos = al(pos, 4)
        dh = u32(b, pos); end = pos + 4 + dh; pos += 4
        n = u32(b, pos); pos += 4
        for _ in range(n):
            assert b[pos] == want, (name, hex(b[pos]))
            h = b[pos+1:pos+15]; pos += 15
            pos = al(pos, 4)
            L = u32(b, pos)
            to = b[pos:pos+4+L]
            pos += 4 + L
            assert hashlib.md5(to).digest()[:14] == h, ("md5 mismatch", name, h.hex())
            objs[h.hex()] = ('M' if want == 0xf1 else 'C', to)
        assert pos == end, (name, pos, end)

topic = {}  # name -> (minimal hash, complete hash)
for name, body in re.findall(r'#define TYPE_INFO_CDR_(\w+) \(const unsigned char \[\]\)\{ \\\n(.*?)\}', src, re.S):
    b = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-f]{2})', body))
    assert u32(b, 4) == 0x40001001 and b[20] == 0xf1
    mh = b[21:35].hex()
    p2 = 12 + u32(b, 8)
    assert u32(b, p2) == 0x40001002 and b[p2+16] == 0xf2
    ch = b[p2+17:p2+31].hex()
    topic[name] = (mh, ch)

def ti(b, p):
    """Parse a TypeIdentifier at p; return (node, end)."""
    d = b[p]; p += 1
    if d <= 0x11: return (('prim', d), p)
    if d in (0x70, 0x72): return (('strs', d, b[p]), p + 1)
    if d in (0x71, 0x73):
        p = al(p, 4); return (('strl', d, u32(b, p)), p + 4)
    if d in (0xf1, 0xf2): return (('hash', b[p:p+14].hex()), p + 14)
    if d in (0x80, 0x81, 0x90, 0x91, 0xa0, 0xa1):
        ek = b[p]; p = al(p + 1, 2); p += 2  # equiv_kind, element_flags
        if d == 0x80 or d == 0xa0: p += 1
        elif d == 0x81 or d == 0xa1: p = al(p, 4) + 4
        elif d == 0x90:
            p = al(p, 4); n = u32(b, p); p += 4 + n
        elif d == 0x91:
            p = al(p, 4); n = u32(b, p); p += 4 + 4 * n
        el, p = ti(b, p)
        kids = [el]
        if d in (0xa0, 0xa1):
            p = al(p, 2) + 2
            k, p = ti(b, p); kids.append(k)
        return (('coll', d, kids), p)
    raise ValueError(hex(d))

def refs(to):
    """Ordered member/related/discriminator TypeIdentifiers of a TypeObject."""
    tk = to[5]; out = []
    if tk == 0x51:
        p = 8; dh = u32(to, p); base, _ = ti(to, p + 4); out.append(base)
        p = al(p + 4 + dh, 4); p += 4; n = u32(to, p); p += 4
        for _ in range(n):
            p = al(p, 4); dh = u32(to, p)
            node, _ = ti(to, p + 4 + 6); out.append(node)
            p += 4 + dh
    elif tk == 0x52:
        p = 8; p = al(p + 4 + u32(to, p), 4)
        node, _ = ti(to, p + 4 + 2); out.append(node)
        p = al(p + 4 + u32(to, p), 4); p += 4; n = u32(to, p); p += 4
        for _ in range(n):
            p = al(p, 4); dh = u32(to, p)
            node, _ = ti(to, p + 4 + 6); out.append(node)
            p += 4 + dh
    elif tk == 0x30:
        p = 8; p = al(p + 4 + u32(to, p), 4)
        node, _ = ti(to, p + 4 + 2); out.append(node)
    return out

def pair(c, m, names, todo):
    if c[0] == 'hash' and m[0] == 'hash':
        todo.append((c[1], m[1]))
    elif c[0] == 'coll' and m[0] == 'coll':
        for x, y in zip(c[2], m[2]): pair(x, y, names, todo)

def cname(to):
    for p in range(8, len(to) - 4, 4):
        L = u32(to, p)
        if 2 <= L <= 256 and p + 4 + L <= len(to) and to[p+4+L-1] == 0:
            s = to[p+4:p+4+L-1]
            if re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_:]*', s):
                return s.decode()
    raise ValueError(to.hex())

names = {}
for h, (k, to) in objs.items():
    if k == 'C': names[h] = cname(to)
todo = []
for t, (mh, ch) in topic.items():
    todo.append((ch, mh))
seen = set()
while todo:
    ch, mh = todo.pop()
    if (ch, mh) in seen: continue
    seen.add((ch, mh))
    if ch not in names: continue
    if mh in names: assert names[mh] == names[ch], (names[mh], names[ch])
    names[mh] = names[ch]
    rc, rm = refs(objs[ch][1]), refs(objs[mh][1])
    assert len(rc) == len(rm), names[ch]
    for x, y in zip(rc, rm): pair(x, y, names, todo)

rows = []
for h, (k, to) in objs.items():
    rows.append((names.get(h, '?'), k, h, to.hex()))
for r in sorted(rows):
    print(*r)
