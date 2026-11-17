// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Foreign oracle for TypeObject annotation records: Fast DDS 3.4 serializes
// them with its own (Annex B generated) code, XCDR2 little endian, origin 0.
// The bytes it prints are the wire tests of xtypes/cdr2/annotations.rs.
//   g++ -std=c++17 -I<fastdds>/include fastdds_annotation_probe.cpp \
//       -L<fastdds>/lib -lfastdds -lfastcdr
#include <cstdio>
#include <vector>
#include <fastcdr/Cdr.h>
#include <fastcdr/FastBuffer.h>
#include <fastdds/dds/xtypes/type_representation/TypeObject.hpp>
using namespace eprosima::fastdds::dds::xtypes;

template<class T> void dump(const char* name, const T& v) {
    std::vector<char> buf(4096, 0);
    eprosima::fastcdr::FastBuffer fb(buf.data(), buf.size());
    eprosima::fastcdr::Cdr ser(fb, eprosima::fastcdr::Cdr::LITTLE_ENDIANNESS, eprosima::fastcdr::CdrVersion::XCDRv2);
    ser << v;
    printf("%s ", name);
    for (size_t i = 0; i < ser.get_serialized_data_length(); i++) printf("%02x", (unsigned char)buf[i]);
    printf("\n");
}

int main() {
    // An applied custom annotation: annotation_typeid = EK_COMPLETE hash
    // 0x11..0x1e, one parameter (an arbitrary name hash, 2c634cbb;
    // MD5("value") starts 2063c160) = int32 7.
    EquivalenceHash h; for (int i = 0; i < 14; i++) h[i] = 0x11 + i;
    TypeIdentifier ti; ti.equivalence_hash(h); ti._d(EK_COMPLETE);
    AppliedAnnotationParameter p;
    NameHash nh = {{0x2c, 0x63, 0x4c, 0xbb}};
    p.paramname_hash(nh);
    AnnotationParameterValue val; val.int32_value(7);
    p.value(val);
    AppliedAnnotation a;
    a.annotation_typeid(ti);
    AppliedAnnotationParameterSeq ps; ps.push_back(p);
    a.param_seq(ps);
    dump("AppliedAnnotationParameter", p);
    dump("AppliedAnnotation", a);
    AppliedAnnotation a0; a0.annotation_typeid(ti);
    dump("AppliedAnnotationNoParams", a0);

    CompleteMemberDetail md; md.name("m");
    AppliedAnnotationSeq as; as.push_back(a); md.ann_custom(as);
    dump("CompleteMemberDetailCustom", md);

    AppliedVerbatimAnnotation v; v.placement("BEGIN_FILE"); v.language("c++"); v.text("// hi");
    AppliedBuiltinTypeAnnotations bt; bt.verbatim(v);
    CompleteTypeDetail td; td.ann_builtin(bt); td.type_name("T");
    dump("CompleteTypeDetailVerbatim", td);

    // Every case of AnnotationParameterValue (Annex B, spec text lines
    // 12611-12654), alone at origin 0.
    { AnnotationParameterValue x; x.boolean_value(true); dump("APV_boolean", x); }
    { AnnotationParameterValue x; x.byte_value(0xAB); dump("APV_byte", x); }
    { AnnotationParameterValue x; x.int8_value(-2); dump("APV_int8", x); }
    { AnnotationParameterValue x; x.uint8_value(0xFE); dump("APV_uint8", x); }
    { AnnotationParameterValue x; x.int16_value(-300); dump("APV_int16", x); }
    { AnnotationParameterValue x; x.uint_16_value(60000); dump("APV_uint16", x); }
    { AnnotationParameterValue x; x.int32_value(-3); dump("APV_int32", x); }
    { AnnotationParameterValue x; x.uint32_value(4000000000u); dump("APV_uint32", x); }
    { AnnotationParameterValue x; x.int64_value(-5000000000LL); dump("APV_int64", x); }
    { AnnotationParameterValue x; x.uint64_value(18000000000000000000ULL); dump("APV_uint64", x); }
    { AnnotationParameterValue x; x.float32_value(1.5f); dump("APV_float32", x); }
    { AnnotationParameterValue x; x.float64_value(2.25); dump("APV_float64", x); }
    { AnnotationParameterValue x; x.float128_value(1.0L); dump("APV_float128", x); }
    { AnnotationParameterValue x; x.char_value('Z'); dump("APV_char8", x); }
    { AnnotationParameterValue x; x.wchar_value(L'\u00e9'); dump("APV_char16", x); }
    { AnnotationParameterValue x; x.enumerated_value(5); dump("APV_enum", x); }
    { AnnotationParameterValue x; x.string8_value("abc"); dump("APV_string8", x); }
    { AnnotationParameterValue x; x.string16_value(L"h\u00e9"); dump("APV_string16", x); }
    { AnnotationParameterValue x; x.extended_value(ExtendedAnnotationParameterValue()); dump("APV_extended", x); }
    return 0;
}
