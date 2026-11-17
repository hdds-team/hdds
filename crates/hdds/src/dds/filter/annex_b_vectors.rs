// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Test vectors derived from DDS 1.4 Annex B "Syntax for Queries and Filters".
//!
//! Every vector names the grammar rule (B.2 "SQL grammar in BNF") or the
//! token definition (B.2 "Token expression") it exercises. The acceptance
//! vectors are productions of the grammar; the rejection vectors are strings
//! that no production derives. The evaluation vectors fix the semantics the
//! specification leaves implicit (type coercion, BETWEEN bounds, LIKE
//! wildcards, operator precedence) and are documented as such in the module
//! documentation of `dds::filter`.
//!
//! The vectors are written against the specification text, independently of
//! the parser implementation.

use super::{parse_expression, ContentFilter, FieldValue, FilterError};
use std::collections::HashMap;

/// Strings that the Annex B grammar derives. `(rule, expression)`.
const ACCEPT: &[(&str, &str)] = &[
    // Condition ::= Predicate | Condition AND Condition | Condition OR Condition
    //             | NOT Condition | ( Condition )
    ("Condition ::= Predicate", "x = 1"),
    ("Condition ::= Condition AND Condition", "x = 1 AND y = 2"),
    ("Condition ::= Condition OR Condition", "x = 1 OR y = 2"),
    ("Condition ::= NOT Condition", "NOT x = 1"),
    ("Condition ::= NOT Condition (nested)", "NOT NOT x = 1"),
    ("Condition ::= NOT ( Condition )", "NOT (x = 1 AND y = 2)"),
    ("Condition ::= ( Condition )", "(x = 1)"),
    (
        "Condition ::= ( Condition ) nested",
        "((x = 1) OR (y = 2)) AND NOT (z = 3)",
    ),
    ("Condition chain", "x = 1 AND y = 2 AND z = 3 OR w = 4"),
    (
        "Condition keywords are case-insensitive",
        "x = 1 and y = 2 or not z = 3",
    ),
    (
        "Condition whitespace: tab and newline",
        "x\t=\n1 AND\r\ny = 2",
    ),
    ("Condition whitespace: none around RelOp", "x=1"),
    ("Condition whitespace: none around >=", "x>=1"),
    ("Condition whitespace: none around <>", "x<>1"),
    ("Condition leading and trailing whitespace", "  x = 1  "),
    // ComparisonPredicate ::= FIELDNAME RelOp Parameter
    //                       | Parameter RelOp FIELDNAME
    //                       | FIELDNAME RelOp FIELDNAME
    ("ComparisonPredicate ::= FIELDNAME RelOp Parameter", "x > 1"),
    ("ComparisonPredicate ::= Parameter RelOp FIELDNAME", "1 < x"),
    (
        "ComparisonPredicate ::= PARAMETER RelOp FIELDNAME",
        "%0 = x",
    ),
    (
        "ComparisonPredicate ::= STRING RelOp FIELDNAME",
        "'RED' = color",
    ),
    ("ComparisonPredicate ::= FIELDNAME RelOp FIELDNAME", "x < y"),
    (
        "ComparisonPredicate ::= FIELDNAME RelOp FIELDNAME (dotted)",
        "pos.x = pos.y",
    ),
    // RelOp ::= = | > | >= | < | <= | <> | like
    ("RelOp ::= =", "x = 1"),
    ("RelOp ::= >", "x > 1"),
    ("RelOp ::= >=", "x >= 1"),
    ("RelOp ::= <", "x < 1"),
    ("RelOp ::= <=", "x <= 1"),
    ("RelOp ::= <>", "x <> 1"),
    (
        "RelOp ::= like (lower case as printed in B.2)",
        "name like 'a%'",
    ),
    ("RelOp ::= like (upper case)", "name LIKE '%'"),
    ("RelOp ::= like (mixed case)", "name Like 'a_c'"),
    // BetweenPredicate ::= FIELDNAME BETWEEN Range | FIELDNAME NOT BETWEEN Range
    // Range ::= Parameter AND Parameter
    (
        "BetweenPredicate ::= FIELDNAME BETWEEN Range",
        "x BETWEEN 1 AND 10",
    ),
    (
        "BetweenPredicate ::= FIELDNAME NOT BETWEEN Range",
        "x NOT BETWEEN 1 AND 10",
    ),
    (
        "BetweenPredicate keywords lower case",
        "x between %0 and %1",
    ),
    (
        "Range ::= FLOATVALUE AND FLOATVALUE",
        "f BETWEEN -1.5 AND 1e2",
    ),
    ("Range ::= STRING AND STRING", "name BETWEEN 'a' AND 'z'"),
    (
        "Range ::= INTEGERVALUE(hex) AND INTEGERVALUE(hex)",
        "x NOT BETWEEN 0x00 AND 0xFF",
    ),
    (
        "BetweenPredicate followed by AND Condition",
        "x BETWEEN 1 AND 10 AND y = 2",
    ),
    (
        "NOT Condition where Condition is a BetweenPredicate",
        "NOT x BETWEEN 1 AND 10",
    ),
    // FIELDNAME: dots navigate nested structures, unlimited depth
    ("FIELDNAME one dot", "pos.x = 1"),
    ("FIELDNAME many dots", "a.b.c.d.e.f = 1"),
    // IDL 4.2 7.2.3: a leading underscore escapes a keyword-like identifier
    // and is not part of the member name; `_leading` names member `leading`.
    ("FIELDNAME escaped IDL identifier", "_leading = 1"),
    // Annex B reserves no word for FIELDNAME; position disambiguates.
    ("FIELDNAME spelled like ORDER", "order = 1"),
    ("FIELDNAME spelled like BY", "by = 1"),
    ("FIELDNAME spelled like BETWEEN", "between = 1"),
    ("FIELDNAME spelled like AND", "and = 1"),
    ("FIELDNAME spelled like LIKE", "like = 1"),
    ("FIELDNAME spelled like ORDER on the right", "x = order"),
    ("FIELDNAME spelled like BETWEEN on the right", "x = between"),
    (
        "FIELDNAME spelled like ORDER in BetweenPredicate",
        "order BETWEEN 1 AND 2",
    ),
    (
        "FIELDNAME spelled like ORDER after AND",
        "x = 1 AND order = 2",
    ),
    ("FIELDNAME escaped keyword", "_and = 1 AND _not = 2"),
    ("FIELDNAME mixed case and digits", "Mixed_Case9 = 1"),
    ("FIELDNAME digit after first character", "x9 = 1"),
    // INTEGERVALUE: digits, optional sign, hexadecimal preceded by 0x
    ("INTEGERVALUE zero", "x = 0"),
    ("INTEGERVALUE decimal", "x = 42"),
    ("INTEGERVALUE minus sign", "x = -42"),
    ("INTEGERVALUE plus sign", "x = +42"),
    ("INTEGERVALUE hexadecimal upper digits", "x = 0x1F"),
    ("INTEGERVALUE hexadecimal lower digits", "x = 0xff"),
    ("INTEGERVALUE hexadecimal 0X prefix", "x = 0X1f"),
    ("INTEGERVALUE signed hexadecimal", "x = -0x10"),
    ("INTEGERVALUE i64::MAX", "x = 9223372036854775807"),
    ("INTEGERVALUE i64::MIN", "x = -9223372036854775808"),
    ("INTEGERVALUE u64::MAX", "x = 18446744073709551615"),
    (
        "INTEGERVALUE u64::MAX hexadecimal",
        "x = 0xFFFFFFFFFFFFFFFF",
    ),
    ("INTEGERVALUE leading zeros", "x = 007"),
    // FLOATVALUE makes both the point and the exponent optional, so a digit
    // series beyond the integer range still has a FLOATVALUE derivation.
    (
        "FLOATVALUE: digits above u64::MAX",
        "x = 18446744073709551616",
    ),
    (
        "FLOATVALUE: digits below i64::MIN",
        "x = -9223372036854775809",
    ),
    (
        "FLOATVALUE: large exponent is still FLOATVALUE syntax",
        "f = 1e308",
    ),
    // FLOATVALUE: digits, optional sign, optional '.', optional e n exponent
    ("FLOATVALUE point", "f = 1.5"),
    ("FLOATVALUE minus sign", "f = -1.5"),
    ("FLOATVALUE plus sign", "f = +1.5"),
    ("FLOATVALUE trailing point", "f = 1."),
    ("FLOATVALUE leading point", "f = .5"),
    ("FLOATVALUE exponent without point", "f = 1e3"),
    ("FLOATVALUE exponent upper case E", "f = 1E3"),
    ("FLOATVALUE exponent negative", "f = 1.5e-3"),
    ("FLOATVALUE exponent positive sign", "f = 1.5e+3"),
    ("FLOATVALUE signed mantissa and exponent", "f = -2.5E-2"),
    ("FLOATVALUE leading point with exponent", "f = .5e1"),
    ("FLOATVALUE trailing point with exponent", "f = 1.e2"),
    // CHARVALUE: a single character between single quotes
    ("CHARVALUE letter", "c = 'A'"),
    ("CHARVALUE space", "c = ' '"),
    ("CHARVALUE percent sign is an ordinary character", "c = '%'"),
    // Annex B excludes the new-line and the right quote from STRING only;
    // a CHARVALUE is "a single character enclosed between single quotes".
    ("CHARVALUE right quote", "c = '''"),
    ("CHARVALUE new-line", "c = '\n'"),
    // STRING: characters in single quotes, no newline, no right quote inside;
    // starts with a left or right quote, ends with a right quote
    ("STRING word", "name = 'hello'"),
    ("STRING empty", "name = ''"),
    ("STRING with space", "name = 'with space'"),
    ("STRING containing a double quote", "name = 'a\"b'"),
    ("STRING opened by a left quote", "name = `left'"),
    ("STRING containing a tab", "name = 'tab\tinside'"),
    ("STRING containing non-ASCII", "name = 'caf\u{e9}'"),
    ("STRING containing keyword text", "name = 'AND'"),
    // ENUMERATEDVALUE: enumeration label in single quotes
    ("ENUMERATEDVALUE", "color = 'RED'"),
    ("ENUMERATEDVALUE on the left", "'RED' = color"),
    // PARAMETER: %n with 0 <= n < 100
    ("PARAMETER %0", "x = %0"),
    ("PARAMETER %9", "x = %9"),
    ("PARAMETER %99 (largest)", "x = %99"),
    ("PARAMETER leading zero", "x = %07"),
    ("PARAMETER in Range", "x BETWEEN %0 AND %1"),
    ("PARAMETER as LIKE pattern", "name LIKE %0"),
    // Boolean literal: not an Annex B token. Kept as a documented extension
    // on the Parameter side of a ComparisonPredicate only (see module doc).
    ("Extension: TRUE as Parameter", "flag = TRUE"),
    ("Extension: FALSE as Parameter", "flag = false"),
    // Local aliases of RelOp, canonicalized to '<>' and '=' when stored.
    ("Extension: != alias of <>", "x != 1"),
    ("Extension: == alias of =", "x == 1"),
];

/// Strings that no Annex B production derives. `(rule violated, expression)`.
const REJECT: &[(&str, &str)] = &[
    // FilterExpression ::= Condition (non-empty)
    ("FilterExpression: empty", ""),
    ("FilterExpression: whitespace only", "   "),
    // Condition
    ("Condition: dangling AND", "x = 1 AND"),
    ("Condition: leading AND", "AND x = 1"),
    ("Condition: dangling OR", "x = 1 OR"),
    ("Condition: NOT without operand", "NOT"),
    ("Condition: unclosed parenthesis", "(x = 1"),
    ("Condition: unopened parenthesis", "x = 1)"),
    ("Condition: empty parentheses", "()"),
    (
        "Condition: two predicates without connective",
        "x = 1 y = 2",
    ),
    ("Condition: doubled connective", "x = 1 AND AND y = 2"),
    ("Condition: trailing garbage", "x = 1 garbage"),
    (
        "Condition: trailing semicolon (TopicExpression only)",
        "x = 1;",
    ),
    ("Condition: SQL comment", "x = 1 -- comment"),
    // ComparisonPredicate: at least one side is a FIELDNAME
    (
        "ComparisonPredicate: INTEGERVALUE RelOp INTEGERVALUE",
        "1 = 1",
    ),
    ("ComparisonPredicate: PARAMETER RelOp PARAMETER", "%0 = %1"),
    ("ComparisonPredicate: STRING RelOp STRING", "'a' = 'b'"),
    (
        "ComparisonPredicate: INTEGERVALUE RelOp PARAMETER",
        "1 = %0",
    ),
    ("ComparisonPredicate: FIELDNAME alone", "x"),
    ("ComparisonPredicate: missing right operand", "x ="),
    ("ComparisonPredicate: missing left operand", "= 1"),
    ("ComparisonPredicate: doubled RelOp", "x = = 1"),
    ("ComparisonPredicate: missing RelOp", "x 1"),
    ("ComparisonPredicate: two right operands", "x = 1 2"),
    ("ComparisonPredicate: Parameter alone", "0"),
    // RelOp: only = > >= < <= <> like
    ("RelOp: =>", "x => 1"),
    ("RelOp: =<", "x =< 1"),
    ("RelOp: ><", "x >< 1"),
    ("RelOp: bare !", "x ! 1"),
    ("RelOp: misspelt like", "name LIKES 'a'"),
    ("RelOp: like without pattern", "name LIKE"),
    ("RelOp: NOT LIKE is not a production", "name NOT LIKE 'a'"),
    // BetweenPredicate / Range
    ("BetweenPredicate: missing AND upper", "x BETWEEN 1"),
    ("BetweenPredicate: missing upper", "x BETWEEN 1 AND"),
    ("BetweenPredicate: missing lower", "x BETWEEN AND 2"),
    (
        "Range: FIELDNAME is not a Parameter (lower)",
        "x BETWEEN y AND 10",
    ),
    (
        "Range: FIELDNAME is not a Parameter (upper)",
        "x BETWEEN 1 AND y",
    ),
    (
        "BetweenPredicate: left side must be FIELDNAME",
        "1 BETWEEN 1 AND 2",
    ),
    (
        "BetweenPredicate: PARAMETER left side",
        "%0 BETWEEN 1 AND 2",
    ),
    ("BetweenPredicate: NOT without BETWEEN", "x NOT 1 AND 2"),
    ("Range: OR instead of AND", "x BETWEEN 1 OR 2"),
    // The boolean extension is a ComparisonPredicate Parameter only.
    ("Range: boolean literal bounds", "x BETWEEN TRUE AND FALSE"),
    (
        "Range: boolean literal upper bound",
        "flag BETWEEN 0 AND TRUE",
    ),
    (
        "BetweenPredicate: NOT BETWEEN missing Range",
        "x NOT BETWEEN 1",
    ),
    // FIELDNAME
    ("FIELDNAME: trailing dot", "pos. = 1"),
    ("FIELDNAME: leading dot", ".x = 1"),
    ("FIELDNAME: empty component", "pos..x = 1"),
    (
        "FIELDNAME: array index is not defined in Annex B",
        "a[0] = 1",
    ),
    ("FIELDNAME: component starting with a digit", "pos.1 = 1"),
    ("FIELDNAME: starting with a digit", "9x = 1"),
    ("FIELDNAME: hyphen (TOPICNAME only)", "a-b = 1"),
    (
        "FIELDNAME: non-ASCII identifier (IDL identifiers are ASCII)",
        "caf\u{e9} = 1",
    ),
    ("FIELDNAME: at sign", "@x = 1"),
    // IDL 4.2 7.2.3: after the optional escape underscore an identifier
    // starts with a letter; one escape at most.
    ("FIELDNAME: escape underscore then digit", "_9 = 1"),
    ("FIELDNAME: two escape underscores", "__x = 1"),
    ("FIELDNAME: bare escape underscore", "_ = 1"),
    ("FIELDNAME: bare escape underscore component", "x._ = 1"),
    // The two words that are keywords by position: NOT opens a Condition,
    // TRUE/FALSE are the boolean extension after a RelOp.
    (
        "Condition: NOT at the start of a Condition is the keyword",
        "not = 1",
    ),
    // INTEGERVALUE
    ("INTEGERVALUE: 0x without digits", "x = 0x"),
    ("INTEGERVALUE: invalid hexadecimal digit", "x = 0xG1"),
    ("INTEGERVALUE: space between sign and digits", "x = - 5"),
    ("INTEGERVALUE: digit separator", "x = 1_000"),
    ("INTEGERVALUE: doubled sign", "x = --5"),
    ("INTEGERVALUE: mixed signs", "x = +-5"),
    ("INTEGERVALUE: binary prefix", "x = 0b101"),
    ("INTEGERVALUE: octal prefix", "x = 0o7"),
    ("INTEGERVALUE: hexadecimal with fraction", "x = 0x1.8"),
    // FLOATVALUE
    ("FLOATVALUE: exponent without digits", "f = 1e"),
    ("FLOATVALUE: exponent sign without digits", "f = 1e+"),
    ("FLOATVALUE: two points", "f = 1.2.3"),
    ("FLOATVALUE: fractional exponent", "f = 1e3.5"),
    ("FLOATVALUE: lone point", "f = ."),
    ("FLOATVALUE: doubled exponent marker", "f = 1ee3"),
    ("FLOATVALUE: type suffix", "f = 1.5f"),
    ("FLOATVALUE: dangling exponent sign", "f = 1.5e-"),
    // CHARVALUE / STRING
    ("STRING: unterminated", "name = 'abc"),
    (
        "STRING: double quotes are not Annex B quotes",
        "name = \"abc\"",
    ),
    ("STRING: right quote inside", "name = 'a'b'"),
    ("STRING: newline inside", "name = 'line\nbreak'"),
    ("STRING: left quote cannot close", "name = `abc`"),
    ("STRING: two adjacent strings", "name = '' ''"),
    // PARAMETER: n < 100
    ("PARAMETER: %100 is out of range", "x = %100"),
    ("PARAMETER: %1000 is out of range", "x = %1000"),
    ("PARAMETER: % without digits", "x = %"),
    ("PARAMETER: non-digit index", "x = %a"),
    ("PARAMETER: negative index", "x = %-1"),
    ("PARAMETER: space after %", "x = % 0"),
    ("PARAMETER: fractional index", "x = %0.5"),
    ("PARAMETER: two adjacent parameters", "x = %0%1"),
    // Non-productions from other SQL dialects or other Annex B branches
    ("Condition: bare boolean literal", "TRUE"),
    ("Condition: bare boolean literal", "FALSE"),
    ("Condition: boolean literal as Condition", "TRUE OR x = 1"),
    ("Condition: boolean literal as Condition", "x = 1 AND FALSE"),
    ("Condition: NOT boolean literal", "NOT TRUE"),
    (
        "ComparisonPredicate: boolean literal both sides",
        "TRUE = TRUE",
    ),
    ("Not Annex B: IS NULL", "x IS NULL"),
    ("Not Annex B: IN list", "x IN (1, 2)"),
    (
        "Expression ::= TopicExpression is not a FilterExpression",
        "SELECT * FROM t",
    ),
    (
        "QueryExpression ORDER BY is not a FilterExpression",
        "x = 1 ORDER BY x",
    ),
];

/// Field map shared by the evaluation vectors. Nested structures are exposed
/// under their dotted path (the FIELDNAME the expression uses).
fn fields() -> HashMap<String, FieldValue> {
    HashMap::from([
        ("x".to_string(), FieldValue::Integer(10)),
        ("y".to_string(), FieldValue::Integer(20)),
        ("z".to_string(), FieldValue::Integer(-3)),
        ("u".to_string(), FieldValue::Unsigned(u64::MAX)),
        ("f".to_string(), FieldValue::Float(2.5)),
        ("g".to_string(), FieldValue::Float(-0.5)),
        ("name".to_string(), FieldValue::String("hello".to_string())),
        ("color".to_string(), FieldValue::String("RED".to_string())),
        ("c".to_string(), FieldValue::String("A".to_string())),
        ("ch".to_string(), FieldValue::Unsigned(65)),
        ("flag".to_string(), FieldValue::Boolean(true)),
        ("off".to_string(), FieldValue::Boolean(false)),
        ("pos.x".to_string(), FieldValue::Integer(3)),
        ("pos.y".to_string(), FieldValue::Integer(4)),
        ("pos.inner.depth".to_string(), FieldValue::Float(1e3)),
        ("label".to_string(), FieldValue::String("TRUE".to_string())),
        (
            "apostrophe".to_string(),
            FieldValue::String("'".to_string()),
        ),
        ("leading".to_string(), FieldValue::Integer(3)),
        ("order".to_string(), FieldValue::Integer(10)),
        ("and".to_string(), FieldValue::Integer(7)),
    ])
}

/// Evaluation vectors. `(rule, expression, parameters, expected)`.
const EVAL: &[(&str, &str, &[&str], bool)] = &[
    // ComparisonPredicate ::= FIELDNAME RelOp Parameter
    ("FIELDNAME = INTEGERVALUE", "x = 10", &[], true),
    ("FIELDNAME = INTEGERVALUE(hex)", "x = 0xA", &[], true),
    ("FIELDNAME = INTEGERVALUE(+)", "x = +10", &[], true),
    ("FIELDNAME = FLOATVALUE(exponent)", "x = 1e1", &[], true),
    ("FIELDNAME <> INTEGERVALUE", "x <> 10", &[], false),
    ("FIELDNAME > INTEGERVALUE", "x > 9", &[], true),
    ("FIELDNAME >= INTEGERVALUE", "x >= 10", &[], true),
    ("FIELDNAME < INTEGERVALUE", "x < 10", &[], false),
    ("FIELDNAME <= INTEGERVALUE", "x <= 10", &[], true),
    // ComparisonPredicate ::= Parameter RelOp FIELDNAME
    ("INTEGERVALUE = FIELDNAME", "10 = x", &[], true),
    ("INTEGERVALUE > FIELDNAME", "11 > x", &[], true),
    ("PARAMETER < FIELDNAME", "%0 < x", &["9"], true),
    // ComparisonPredicate ::= FIELDNAME RelOp FIELDNAME
    ("FIELDNAME < FIELDNAME", "x < y", &[], true),
    (
        "FIELDNAME(dotted) < FIELDNAME(dotted)",
        "pos.x < pos.y",
        &[],
        true,
    ),
    ("FIELDNAME = FIELDNAME", "x = y", &[], false),
    // FIELDNAME with dots resolves through the field map
    ("FIELDNAME one dot", "pos.x = 3", &[], true),
    ("FIELDNAME two dots", "pos.inner.depth = 1000", &[], true),
    (
        "FIELDNAME two dots vs exponent",
        "pos.inner.depth = 1e3",
        &[],
        true,
    ),
    (
        "FIELDNAME two dots vs signed exponent",
        "pos.inner.depth >= 1E+3",
        &[],
        true,
    ),
    (
        "FIELDNAME escaped identifier resolves to the member",
        "_leading = 3",
        &[],
        true,
    ),
    (
        "FIELDNAME escaped identifier on the right",
        "3 = _leading",
        &[],
        true,
    ),
    ("FIELDNAME spelled like ORDER", "order = 10", &[], true),
    (
        "FIELDNAME spelled like ORDER on the right",
        "x = order",
        &[],
        true,
    ),
    (
        "FIELDNAME spelled like ORDER in BetweenPredicate",
        "order BETWEEN 9 AND 11",
        &[],
        true,
    ),
    (
        "FIELDNAME escaped keyword",
        "_and = 7 AND and = 7",
        &[],
        true,
    ),
    // INTEGERVALUE
    (
        "INTEGERVALUE hex u64::MAX",
        "u = 0xFFFFFFFFFFFFFFFF",
        &[],
        true,
    ),
    ("INTEGERVALUE signed hex", "z = -0x3", &[], true),
    ("INTEGERVALUE negative", "z = -3", &[], true),
    (
        "INTEGERVALUE leading zeros are decimal",
        "x = 0010",
        &[],
        true,
    ),
    (
        "FLOATVALUE digits above u64::MAX (binary64)",
        "u < 18446744073709551616",
        &[],
        true,
    ),
    (
        "FLOATVALUE digits below i64::MIN (binary64)",
        "z > -9223372036854775809",
        &[],
        true,
    ),
    // FLOATVALUE
    ("FLOATVALUE point", "f = 2.5", &[], true),
    ("FLOATVALUE exponent", "f = 25e-1", &[], true),
    (
        "FLOATVALUE leading point with exponent",
        "f = .25e1",
        &[],
        true,
    ),
    ("FLOATVALUE trailing point", "f > 2.", &[], true),
    ("FLOATVALUE negative leading point", "g = -.5", &[], true),
    ("FLOATVALUE negative exponent form", "g = -5E-1", &[], true),
    // CHARVALUE: against a string field it is a one-character string; against
    // an integer field (IDL char carried as an integer) it is the code point.
    ("CHARVALUE = string field", "c = 'A'", &[], true),
    ("CHARVALUE <> string field", "c = 'B'", &[], false),
    (
        "CHARVALUE = integer field (code point)",
        "ch = 'A'",
        &[],
        true,
    ),
    (
        "CHARVALUE <> integer field (code point)",
        "ch = 'B'",
        &[],
        false,
    ),
    ("CHARVALUE > integer field", "ch > 'A'", &[], false),
    ("CHARVALUE >= integer field", "ch >= 'A'", &[], true),
    ("CHARVALUE on the left", "'A' = ch", &[], true),
    ("CHARVALUE Range", "ch BETWEEN 'A' AND 'Z'", &[], true),
    (
        "CHARVALUE right quote = string field",
        "apostrophe = '''",
        &[],
        true,
    ),
    (
        "CHARVALUE right quote <> other field",
        "c = '''",
        &[],
        false,
    ),
    ("CHARVALUE right quote code point", "ch = '''", &[], false),
    // STRING: exact, case-sensitive comparison
    ("STRING equal", "name = 'hello'", &[], true),
    ("STRING case-sensitive", "name = 'Hello'", &[], false),
    ("STRING ordered", "name < 'world'", &[], true),
    ("STRING empty", "name = ''", &[], false),
    ("STRING left quote opener", "name = `hello'", &[], true),
    (
        "STRING with double quote inside",
        "name = 'he\"llo'",
        &[],
        false,
    ),
    // ENUMERATEDVALUE: the field map exposes the label
    ("ENUMERATEDVALUE equal", "color = 'RED'", &[], true),
    ("ENUMERATEDVALUE other label", "color = 'BLUE'", &[], false),
    ("ENUMERATEDVALUE on the left", "'RED' = color", &[], true),
    ("ENUMERATEDVALUE <>", "color <> 'RED'", &[], false),
    // PARAMETER: the argument text follows the Parameter token forms
    ("PARAMETER INTEGERVALUE", "x = %0", &["10"], true),
    ("PARAMETER INTEGERVALUE(hex)", "x = %0", &["0xA"], true),
    ("PARAMETER INTEGERVALUE(+)", "x = %0", &["+10"], true),
    ("PARAMETER FLOATVALUE(exponent)", "x = %0", &["1e1"], true),
    ("PARAMETER STRING", "name = %0", &["'hello'"], true),
    (
        "PARAMETER STRING opened by a left quote",
        "name = %0",
        &["`hello'"],
        true,
    ),
    (
        "PARAMETER CHARVALUE opened by a left quote",
        "ch = %0",
        &["`A'"],
        true,
    ),
    (
        "PARAMETER unquoted text (extension)",
        "name = %0",
        &["hello"],
        true,
    ),
    ("PARAMETER ENUMERATEDVALUE", "color = %0", &["'RED'"], true),
    (
        "PARAMETER CHARVALUE vs string field",
        "c = %0",
        &["'A'"],
        true,
    ),
    (
        "PARAMETER CHARVALUE vs integer field",
        "ch = %0",
        &["'A'"],
        true,
    ),
    ("PARAMETER second position", "x = %1", &["0", "10"], true),
    // BetweenPredicate: inclusive bounds, low AND high in that order
    ("BETWEEN inclusive low", "x BETWEEN 10 AND 20", &[], true),
    ("BETWEEN inclusive high", "x BETWEEN 0 AND 10", &[], true),
    ("BETWEEN outside", "x BETWEEN 11 AND 20", &[], false),
    ("NOT BETWEEN outside", "x NOT BETWEEN 11 AND 20", &[], true),
    ("NOT BETWEEN inside", "x NOT BETWEEN 0 AND 20", &[], false),
    (
        "BETWEEN reversed bounds is empty",
        "x BETWEEN 20 AND 0",
        &[],
        false,
    ),
    (
        "BETWEEN float in integer range",
        "f BETWEEN 2 AND 3",
        &[],
        true,
    ),
    (
        "BETWEEN parameters",
        "f BETWEEN %0 AND %1",
        &["2.5", "2.5"],
        true,
    ),
    ("BETWEEN strings", "name BETWEEN 'a' AND 'z'", &[], true),
    ("BETWEEN hex", "x BETWEEN 0x0 AND 0xF", &[], true),
    ("BETWEEN exponents", "x BETWEEN 1e1 AND 1e1", &[], true),
    // like: SQL-92 wildcards, % any sequence, _ one character, case-sensitive
    ("like prefix", "name LIKE 'h%'", &[], true),
    ("like suffix", "name LIKE '%llo'", &[], true),
    ("like single wildcard", "name LIKE 'h_llo'", &[], true),
    (
        "like single wildcard is exactly one",
        "name LIKE 'h_lo'",
        &[],
        false,
    ),
    ("like everything", "name LIKE '%'", &[], true),
    ("like case-sensitive", "name LIKE 'HELLO'", &[], false),
    (
        "like pattern from PARAMETER",
        "name LIKE %0",
        &["'h%'"],
        true,
    ),
    ("like empty pattern", "name LIKE ''", &[], false),
    ("like on enumeration label", "color LIKE 'R__'", &[], true),
    // Condition: precedence NOT > AND > OR, parentheses override
    ("AND both true", "x = 10 AND y = 20", &[], true),
    ("AND one false", "x = 10 AND y = 0", &[], false),
    ("OR one true", "x = 0 OR y = 20", &[], true),
    ("NOT false", "NOT x = 0", &[], true),
    ("NOT true", "NOT x = 10", &[], false),
    (
        "AND binds tighter than OR",
        "x = 0 OR y = 0 AND x = 10",
        &[],
        false,
    ),
    (
        "parentheses override",
        "(x = 0 OR y = 20) AND x = 10",
        &[],
        true,
    ),
    ("OR of AND", "x = 0 OR y = 20 AND x = 10", &[], true),
    (
        "NOT binds tighter than AND",
        "NOT x = 0 AND y = 20",
        &[],
        true,
    ),
    (
        "NOT of parenthesized AND",
        "NOT (x = 0 AND y = 20)",
        &[],
        true,
    ),
    (
        "NOT binds tighter than OR",
        "NOT x = 10 OR y = 20",
        &[],
        true,
    ),
    // Boolean fields: TRUE/FALSE extension, integer 0/1, quoted label
    ("boolean = TRUE", "flag = TRUE", &[], true),
    ("boolean = FALSE", "flag = FALSE", &[], false),
    ("boolean = false (lower case)", "off = false", &[], true),
    ("boolean = 1", "flag = 1", &[], true),
    ("boolean = 0", "flag = 0", &[], false),
    ("boolean false = 0", "off = 0", &[], true),
    ("boolean = 'TRUE'", "flag = 'TRUE'", &[], true),
    (
        "boolean = 'true' (label case-insensitive)",
        "flag = 'true'",
        &[],
        true,
    ),
    ("boolean false = 'FALSE'", "off = 'FALSE'", &[], true),
    ("boolean <> boolean", "flag <> off", &[], true),
    ("boolean = PARAMETER TRUE", "flag = %0", &["TRUE"], true),
    ("boolean = PARAMETER 1", "flag = %0", &["1"], true),
    ("boolean = PARAMETER 'true'", "flag = %0", &["'true'"], true),
    // Local aliases evaluate as the Annex B operator they stand for
    ("alias != is <>", "x != 10", &[], false),
    ("alias != is <> (other value)", "x != 11", &[], true),
    ("alias == is =", "x == 10", &[], true),
    ("alias == is = (other value)", "x == 11", &[], false),
    // Mixed numeric comparisons keep exact ordering
    ("unsigned > signed", "u > x", &[], true),
    (
        "unsigned = u64::MAX literal",
        "u = 18446744073709551615",
        &[],
        true,
    ),
    ("integer = float literal", "x = 10.0", &[], true),
    ("negative integer < negative float", "z < g", &[], true),
    ("float > integer", "f > x", &[], false),
];

/// Representability policy, distinct from the grammar: every string here is
/// derived by Annex B (FLOATVALUE or hexadecimal INTEGERVALUE), and the
/// implementation accepts or refuses it on the documented value range.
/// `(policy, expression, accepted)`.
const REPRESENTABILITY: &[(&str, &str, bool)] = &[
    (
        "policy: decimal digits beyond u64::MAX read as binary64",
        "x = 18446744073709551616",
        true,
    ),
    (
        "policy: decimal digits below i64::MIN read as binary64",
        "x = -9223372036854775809",
        true,
    ),
    (
        "policy: FLOATVALUE must be a finite binary64",
        "f = 1e400",
        false,
    ),
    (
        "policy: FLOATVALUE must be a finite binary64 (negative)",
        "f = -1e400",
        false,
    ),
    (
        "policy: hexadecimal INTEGERVALUE must fit 64 bits (no FLOATVALUE derivation)",
        "x = 0x1FFFFFFFFFFFFFFFF",
        false,
    ),
    (
        "policy: hexadecimal INTEGERVALUE fits 64 bits",
        "x = 0xFFFFFFFFFFFFFFFF",
        true,
    ),
];

/// Expressions that parse but fail at evaluation. `(rule, expression, parameters)`.
const EVAL_ERR: &[(&str, &str, &[&str])] = &[
    ("FIELDNAME unknown", "missing = 1", &[]),
    ("FIELDNAME unknown nested leaf", "pos.z = 1", &[]),
    ("FIELDNAME structure prefix is not a leaf", "pos = 1", &[]),
    ("type: STRING vs integer field", "name = 1", &[]),
    (
        "type: multi-character STRING vs integer field",
        "x = 'ab'",
        &[],
    ),
    ("type: like on integer field", "x LIKE 'a%'", &[]),
    ("type: ordered boolean", "flag > TRUE", &[]),
    ("type: boolean vs integer other than 0/1", "flag = 2", &[]),
    ("type: boolean vs unknown label", "flag = 'yes'", &[]),
    (
        "type: string field BETWEEN integers",
        "name BETWEEN 1 AND 2",
        &[],
    ),
    (
        "type: integer field BETWEEN strings",
        "x BETWEEN 'ab' AND 'cd'",
        &[],
    ),
    // Provenance: coercions apply to a LITERAL against a typed FIELD only.
    // A string field is never read as an integer or a boolean.
    (
        "provenance: one-char string field vs INTEGERVALUE",
        "c = 65",
        &[],
    ),
    (
        "provenance: one-char string field vs integer field",
        "c = ch",
        &[],
    ),
    (
        "provenance: one-char string field BETWEEN integers",
        "c BETWEEN 65 AND 65",
        &[],
    ),
    (
        "provenance: string field vs boolean literal",
        "label = TRUE",
        &[],
    ),
    (
        "provenance: string field vs boolean parameter",
        "label = %0",
        &["TRUE"],
    ),
    (
        "provenance: integer field vs boolean literal",
        "x = TRUE",
        &[],
    ),
    ("PARAMETER missing", "x = %0", &[]),
    ("PARAMETER missing second", "x = %1", &["1"]),
];

fn evaluate(expression: &str, params: &[&str]) -> Result<bool, FilterError> {
    let params: Vec<String> = params.iter().map(|p| p.to_string()).collect();
    let filter = ContentFilter::with_parameters(expression, params)?;
    filter.evaluator().matches(&fields())
}

fn report(kind: &str, total: usize, failures: &[String]) {
    eprintln!(
        "annex_b_vectors {kind}: {} / {total} pass",
        total - failures.len()
    );
    for failure in failures {
        eprintln!("  FAIL {failure}");
    }
    assert!(
        failures.is_empty(),
        "{kind}: {} of {total} vectors failed (see stderr)",
        failures.len()
    );
}

#[test]
fn annex_b_grammar_accepts_every_production() {
    let mut failures = Vec::new();
    for (rule, expression) in ACCEPT {
        if let Err(error) = parse_expression(expression) {
            failures.push(format!("{rule}: {expression:?} -> {error}"));
        }
    }
    report("accept", ACCEPT.len(), &failures);
}

#[test]
fn annex_b_grammar_rejects_every_non_production() {
    let mut failures = Vec::new();
    for (rule, expression) in REJECT {
        if parse_expression(expression).is_ok() {
            failures.push(format!("{rule}: {expression:?} was accepted"));
        }
    }
    report("reject", REJECT.len(), &failures);
}

#[test]
fn annex_b_evaluation_semantics() {
    let mut failures = Vec::new();
    for (rule, expression, params, expected) in EVAL {
        match evaluate(expression, params) {
            Ok(actual) if actual == *expected => {}
            Ok(actual) => failures.push(format!(
                "{rule}: {expression:?} {params:?} -> {actual}, expected {expected}"
            )),
            Err(error) => failures.push(format!(
                "{rule}: {expression:?} {params:?} -> {error}, expected {expected}"
            )),
        }
    }
    report("eval", EVAL.len(), &failures);
}

#[test]
fn annex_b_representability_policy() {
    let mut failures = Vec::new();
    for (policy, expression, accepted) in REPRESENTABILITY {
        if parse_expression(expression).is_ok() != *accepted {
            failures.push(format!(
                "{policy}: {expression:?}, expected accepted={accepted}"
            ));
        }
    }
    report("representability", REPRESENTABILITY.len(), &failures);
}

#[test]
fn annex_b_evaluation_errors() {
    let mut failures = Vec::new();
    for (rule, expression, params) in EVAL_ERR {
        if let Ok(actual) = evaluate(expression, params) {
            failures.push(format!(
                "{rule}: {expression:?} {params:?} -> Ok({actual}), expected an error"
            ));
        }
    }
    report("eval-err", EVAL_ERR.len(), &failures);
}

#[test]
fn annex_b_parameter_range_is_zero_to_ninety_nine() {
    // PARAMETER: "%n, where n represents a natural number (zero included)
    // smaller than 100. It refers to the n + 1 th argument".
    let mut params: Vec<String> = (0..100).map(|_| "0".to_string()).collect();
    params[99] = "10".to_string();
    let filter = ContentFilter::with_parameters("x = %99", params)
        .expect("%99 is the largest Annex B parameter");
    assert_eq!(filter.evaluator().matches(&fields()), Ok(true));
    assert!(matches!(
        parse_expression("x = %100"),
        Err(FilterError::ParseError(_))
    ));
}
