// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Foreign oracle for the TypeObject kinds Cyclone DDS 0.11 idlc does not
// emit as objects: bitset, annotation, and the collection objects (a
// conformant builder names an anonymous collection by a plain
// TypeIdentifier, so idlc never serializes one). Fast DDS 3.4 serializes
// each with its own (Annex B generated) code, XCDR2 little endian, origin
// 0, as the outer TypeObject: DHEADER, EK octet, the Complete/Minimal
// object. Its output is `fastdds-3.4-typeobjects.txt`.
//   g++ -std=c++17 -I<fastdds>/include fastdds_typeobject_probe.cpp \
//       -L<fastdds>/lib -lfastdds -lfastcdr
#include <cstdio>
#include <vector>
#include <fastcdr/Cdr.h>
#include <fastcdr/FastBuffer.h>
#include <fastdds/dds/xtypes/type_representation/TypeObject.hpp>
using namespace eprosima::fastdds::dds::xtypes;

static void dump(const char* name, char kind, const TypeObject& v) {
    std::vector<char> buf(8192, 0);
    eprosima::fastcdr::FastBuffer fb(buf.data(), buf.size());
    eprosima::fastcdr::Cdr ser(fb, eprosima::fastcdr::Cdr::LITTLE_ENDIANNESS,
                               eprosima::fastcdr::CdrVersion::XCDRv2);
    ser << v;
    printf("%s %c ", name, kind);
    for (size_t i = 0; i < ser.get_serialized_data_length(); i++) printf("%02x", (unsigned char)buf[i]);
    printf("\n");
}
static TypeIdentifier prim(uint8_t k) { TypeIdentifier t; t._d(k); return t; }
static void complete(const char* n, const CompleteTypeObject& c) { TypeObject o; o.complete(c); dump(n, 'C', o); }
static void minimal(const char* n, const MinimalTypeObject& m) { TypeObject o; o.minimal(m); dump(n, 'M', o); }

int main() {
    // bitset BS { bitfield<3, uint8> a; bitfield<5, uint8> b; };
    // Fields given in reverse position order: the sequence is ordered by
    // position (Annex B), whatever order they are declared in.
    {
        CommonBitfield c1; c1.position(0); c1.bitcount(3); c1.holder_type(TK_UINT8);
        CommonBitfield c2; c2.position(3); c2.bitcount(5); c2.holder_type(TK_UINT8);
        CompleteBitsetType bs; CompleteBitsetHeader h; CompleteTypeDetail d; d.type_name("BS");
        h.detail(d); bs.header(h);
        CompleteBitfieldSeq fs;
        CompleteBitfield f1; f1.common(c1); CompleteMemberDetail md1; md1.name("a"); f1.detail(md1);
        CompleteBitfield f2; f2.common(c2); CompleteMemberDetail md2; md2.name("b"); f2.detail(md2);
        fs.push_back(f1); fs.push_back(f2); bs.field_seq(fs);
        CompleteTypeObject c; c.bitset_type(bs); complete("Bitset", c);
        MinimalBitsetType mb; MinimalBitfieldSeq mfs;
        MinimalBitfield m1; m1.common(c1); NameHash n1 = {{0x0c, 0xc1, 0x75, 0xb9}}; m1.name_hash(n1);
        MinimalBitfield m2; m2.common(c2); NameHash n2 = {{0x92, 0xeb, 0x5f, 0xfe}}; m2.name_hash(n2);
        mfs.push_back(m1); mfs.push_back(m2); mb.field_seq(mfs);
        MinimalTypeObject m; m.bitset_type(mb); minimal("Bitset", m);
    }
    // @annotation MyAnn { long value default 7; string s default "x"; };
    // (name hashes, MD5 first octets: "value" 2063c160, "s" 03c7c0ac)
    {
        CommonAnnotationParameter cp1; cp1.member_type_id(prim(TK_INT32));
        AnnotationParameterValue v1; v1.int32_value(7);
        TypeIdentifier ts; StringSTypeDefn sd; sd.bound(0); ts.string_sdefn(sd);
        CommonAnnotationParameter cp2; cp2.member_type_id(ts);
        AnnotationParameterValue v2; v2.string8_value("x");
        CompleteAnnotationType a; CompleteAnnotationHeader h; h.annotation_name("MyAnn"); a.header(h);
        CompleteAnnotationParameterSeq ps;
        CompleteAnnotationParameter p1; p1.common(cp1); p1.name("value"); p1.default_value(v1);
        CompleteAnnotationParameter p2; p2.common(cp2); p2.name("s"); p2.default_value(v2);
        ps.push_back(p2); ps.push_back(p1); a.member_seq(ps);
        CompleteTypeObject c; c.annotation_type(a); complete("Annotation", c);
        MinimalAnnotationType ma; MinimalAnnotationParameterSeq mps;
        MinimalAnnotationParameter q1; q1.common(cp1); NameHash h1 = {{0x20, 0x63, 0xc1, 0x60}}; q1.name_hash(h1); q1.default_value(v1);
        MinimalAnnotationParameter q2; q2.common(cp2); NameHash h2 = {{0x03, 0xc7, 0xc0, 0xac}}; q2.name_hash(h2); q2.default_value(v2);
        mps.push_back(q2); mps.push_back(q1); ma.member_seq(mps);
        MinimalTypeObject m; m.annotation_type(ma); minimal("Annotation", m);
    }
    // map<long, long, 5>
    {
        CommonCollectionHeader ch; ch.bound(5);
        CommonCollectionElement ck; ck.type(prim(TK_INT32));
        CommonCollectionElement ce; ce.type(prim(TK_INT32));
        CompleteMapType mp; CompleteCollectionHeader h; h.common(ch); mp.header(h);
        CompleteCollectionElement k; k.common(ck); mp.key(k);
        CompleteCollectionElement e; e.common(ce); mp.element(e);
        CompleteTypeObject c; c.map_type(mp); complete("Map", c);
        MinimalMapType mm; MinimalCollectionHeader mh; mh.common(ch); mm.header(mh);
        MinimalCollectionElement mk; mk.common(ck); mm.key(mk);
        MinimalCollectionElement me; me.common(ce); mm.element(me);
        MinimalTypeObject m; m.map_type(mm); minimal("Map", m);
    }
    // sequence<long, 3>, the Complete header carrying a detail named "S3"
    {
        CommonCollectionHeader ch; ch.bound(3);
        CommonCollectionElement ce; ce.type(prim(TK_INT32));
        CompleteSequenceType sq; CompleteCollectionHeader h; h.common(ch);
        CompleteTypeDetail d; d.type_name("S3"); h.detail(d); sq.header(h);
        CompleteCollectionElement e; e.common(ce); sq.element(e);
        CompleteTypeObject c; c.sequence_type(sq); complete("Sequence", c);
        MinimalSequenceType ms; MinimalCollectionHeader mh; mh.common(ch); ms.header(mh);
        MinimalCollectionElement me; me.common(ce); ms.element(me);
        MinimalTypeObject m; m.sequence_type(ms); minimal("Sequence", m);
    }
    // long[2][3], the Complete header carrying a detail named "A23"
    {
        CommonArrayHeader ch; LBoundSeq b; b.push_back(2); b.push_back(3); ch.bound_seq(b);
        CommonCollectionElement ce; ce.type(prim(TK_INT32));
        CompleteArrayType ar; CompleteArrayHeader h; h.common(ch);
        CompleteTypeDetail d; d.type_name("A23"); h.detail(d); ar.header(h);
        CompleteCollectionElement e; e.common(ce); ar.element(e);
        CompleteTypeObject c; c.array_type(ar); complete("Array", c);
        MinimalArrayType ma; MinimalArrayHeader mh; mh.common(ch); ma.header(mh);
        MinimalCollectionElement me; me.common(ce); ma.element(me);
        MinimalTypeObject m; m.array_type(ma); minimal("Array", m);
    }
    // @final union UD switch (@Ann long) { case 1: long a; }; the
    // discriminator member carrying one applied custom annotation without
    // parameters (annotation_typeid = EK_COMPLETE hash 0x11..0x1e), the
    // CompleteDiscriminatorMember.ann_custom of Annex B
    {
        EquivalenceHash h; for (int i = 0; i < 14; i++) h[i] = 0x11 + i;
        TypeIdentifier ann; ann.equivalence_hash(h); ann._d(EK_COMPLETE);
        AppliedAnnotation a; a.annotation_typeid(ann);
        AppliedAnnotationSeq as; as.push_back(a);
        CommonDiscriminatorMember cd; cd.member_flags(TRY_CONSTRUCT1 | IS_MUST_UNDERSTAND);
        cd.type_id(prim(TK_INT32));
        CompleteDiscriminatorMember disc; disc.common(cd); disc.ann_custom(as);
        CompleteUnionHeader hdr; CompleteTypeDetail d; d.type_name("UD"); hdr.detail(d);
        CommonUnionMember cm; cm.member_id(1); cm.member_flags(TRY_CONSTRUCT1);
        cm.type_id(prim(TK_INT32)); UnionCaseLabelSeq l; l.push_back(1); cm.label_seq(l);
        CompleteMemberDetail md; md.name("a");
        CompleteUnionMember m; m.common(cm); m.detail(md);
        CompleteUnionMemberSeq ms; ms.push_back(m);
        CompleteUnionType u; u.union_flags(IS_FINAL); u.header(hdr); u.discriminator(disc);
        u.member_seq(ms);
        CompleteTypeObject c; c.union_type(u); complete("UnionDiscAnn", c);
    }
    return 0;
}
