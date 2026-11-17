// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Filter Expression Parser
//!
//! Parses DDS 1.4 Annex B filter and query expressions into an AST. The
//! grammar rules and token definitions quoted in this file are those of
//! Annex B "Syntax for Queries and Filters", B.2 "SQL grammar in BNF" and
//! B.2 "Token expression". Every error message names the rule or token that
//! the input violates.

use super::FilterError;

/// `RelOp ::= '=' | '>' | '>=' | '<' | '<=' | '<>' | like` (Annex B, B.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    /// Greater than (>)
    Gt,
    /// Less than (<)
    Lt,
    /// Greater than or equal (>=)
    Ge,
    /// Less than or equal (<=)
    Le,
    /// Equal (=)
    Eq,
    /// Not equal (<>)
    Ne,
    /// `like` pattern matching
    Like,
}

/// Operand of a predicate: an Annex B `Parameter` or a `FIELDNAME`.
///
/// `Parameter ::= INTEGERVALUE | CHARVALUE | FLOATVALUE | STRING |
/// ENUMERATEDVALUE | PARAMETER`. CHARVALUE, STRING and ENUMERATEDVALUE are
/// lexically the same token (text between single quotes) and share the
/// `String` variant; the evaluator tells them apart from the type of the
/// field they are compared with.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// INTEGERVALUE within i64
    Integer(i64),
    /// INTEGERVALUE above i64::MAX, within u64
    Unsigned(u64),
    /// FLOATVALUE
    Float(f64),
    /// CHARVALUE, STRING or ENUMERATEDVALUE (single-quoted text)
    String(String),
    /// Boolean literal `TRUE` / `FALSE`. Not an Annex B token; accepted as a
    /// Parameter for boolean fields (see the module documentation).
    Boolean(bool),
    /// PARAMETER `%n`, 0 <= n <= 99
    Parameter(usize),
    /// FIELDNAME, dots included (`pos.x`)
    Field(String),
}

/// Parsed `Condition` (Annex B, B.2).
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// `ComparisonPredicate ::= FIELDNAME RelOp Parameter | Parameter RelOp
    /// FIELDNAME | FIELDNAME RelOp FIELDNAME`. At least one side is a
    /// `Value::Field`.
    Comparison {
        /// Left operand
        left: Value,
        /// Relational operator
        op: Operator,
        /// Right operand
        right: Value,
    },
    /// `BetweenPredicate ::= FIELDNAME BETWEEN Range | FIELDNAME NOT BETWEEN
    /// Range`, `Range ::= Parameter AND Parameter`. `low` and `high` are never
    /// `Value::Field`.
    Between {
        /// The FIELDNAME on the left
        field: String,
        /// Lower bound (inclusive)
        low: Value,
        /// Upper bound (inclusive)
        high: Value,
        /// `NOT BETWEEN`
        negated: bool,
    },
    /// `Condition AND Condition ...`: a whole chain is one node with two or
    /// more operands, so a long chain never nests. A parenthesized AND inside
    /// an AND is a nested node, as written.
    And(Vec<Expression>),
    /// `Condition OR Condition ...`, same shape as [`Expression::And`].
    Or(Vec<Expression>),
    /// `NOT Condition`
    Not(Box<Expression>),
    /// Always true (matches everything). Never produced by the parser; kept
    /// for callers that build expressions programmatically.
    True,
}

/// Parsed `QueryExpression ::= {Condition}{'ORDER BY' (FIELDNAME // ',')}`
/// (Annex B, B.2).
#[derive(Debug, Clone, PartialEq)]
pub struct QueryExpression {
    /// The optional `Condition`; `None` matches every sample.
    pub condition: Option<Expression>,
    /// The FIELDNAMEs of the optional `ORDER BY` clause, in order.
    pub order_by: Vec<String>,
}

// ---------------------------------------------------------------------------
// Canonical rendering
//
// `Display` renders a parsed expression back to Annex B text: upper-case
// keywords, the Annex B RelOp spellings (the local aliases '!=' and '=='
// come out as '<>' and '='), decimal INTEGERVALUEs, FLOATVALUEs in a form
// the lexer reads back as FLOATVALUE, single-quoted literals, and the
// minimal parentheses that preserve the parsed tree under the NOT > AND > OR
// precedence. `ContentFilter::canonical_expression` returns it; it is the
// only form ever announced or sent on the wire.
// ---------------------------------------------------------------------------

impl std::fmt::Display for Operator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Operator::Gt => ">",
            Operator::Lt => "<",
            Operator::Ge => ">=",
            Operator::Le => "<=",
            Operator::Eq => "=",
            Operator::Ne => "<>",
            Operator::Like => "LIKE",
        })
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Integer(n) => write!(f, "{n}"),
            Value::Unsigned(n) => write!(f, "{n}"),
            // `{:?}` keeps a '.' or an exponent, so the text re-lexes as
            // FLOATVALUE rather than INTEGERVALUE. Non-finite values never
            // reach a parsed expression.
            Value::Float(x) => write!(f, "{x:?}"),
            // The lexer rejects a right quote inside a literal, so no escape
            // is needed or possible.
            Value::String(s) => write!(f, "'{s}'"),
            Value::Boolean(true) => f.write_str("TRUE"),
            Value::Boolean(false) => f.write_str("FALSE"),
            Value::Parameter(n) => write!(f, "%{n}"),
            // A component spelling a keyword is written with its IDL escape
            // underscore, so the canonical text parses the same everywhere
            // (`not` at the start of a Condition would be the keyword).
            Value::Field(name) => write_field_name(f, name),
        }
    }
}

/// Words the parser can read as a keyword by position (upper-cased).
const KEYWORDS: [&str; 9] = [
    "AND", "OR", "NOT", "BETWEEN", "LIKE", "ORDER", "BY", "TRUE", "FALSE",
];

/// Write a FIELDNAME, re-escaping every component that spells a keyword.
fn write_field_name(f: &mut std::fmt::Formatter<'_>, name: &str) -> std::fmt::Result {
    for (index, component) in name.split('.').enumerate() {
        if index > 0 {
            f.write_str(".")?;
        }
        if KEYWORDS.contains(&component.to_ascii_uppercase().as_str()) {
            f.write_str("_")?;
        }
        f.write_str(component)?;
    }
    Ok(())
}

impl Expression {
    /// Binding strength used to decide where parentheses are required.
    fn precedence(&self) -> u8 {
        match self {
            Expression::Or(..) => 0,
            Expression::And(..) => 1,
            Expression::Not(..) => 2,
            Expression::Comparison { .. } | Expression::Between { .. } | Expression::True => 3,
        }
    }

    /// Write `child` with parentheses when it binds more loosely than `min`.
    fn fmt_child(child: &Expression, min: u8, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if child.precedence() < min {
            write!(f, "({child})")
        } else {
            write!(f, "{child}")
        }
    }
}

impl std::fmt::Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expression::Comparison { left, op, right } => write!(f, "{left} {op} {right}"),
            Expression::Between {
                field,
                low,
                high,
                negated,
            } => {
                let keyword = if *negated { "NOT BETWEEN" } else { "BETWEEN" };
                write_field_name(f, field)?;
                write!(f, " {keyword} {low} AND {high}")
            }
            // Every operand of a chain is written with the precedence just
            // above the chain's own, so a nested chain of the same kind (the
            // source's own parentheses) and any looser one are parenthesized.
            Expression::And(items) => {
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" AND ")?;
                    }
                    Expression::fmt_child(item, 2, f)?;
                }
                Ok(())
            }
            Expression::Or(items) => {
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" OR ")?;
                    }
                    Expression::fmt_child(item, 1, f)?;
                }
                Ok(())
            }
            Expression::Not(inner) => {
                f.write_str("NOT ")?;
                Expression::fmt_child(inner, 2, f)
            }
            // No Annex B text derives a tautology; render the closest
            // Condition. A caller that built `True` by hand owns the field.
            Expression::True => f.write_str("TRUE"),
        }
    }
}

impl std::fmt::Display for QueryExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(condition) = &self.condition {
            write!(f, "{condition}")?;
        }
        if !self.order_by.is_empty() {
            if self.condition.is_some() {
                f.write_str(" ")?;
            }
            write!(f, "ORDER BY {}", self.order_by.join(", "))?;
        }
        Ok(())
    }
}

/// Token types for the lexer.
///
/// Annex B reserves no word for FIELDNAME, so an identifier is lexed as a
/// [`Token::Word`] and the parser decides by position whether it is a
/// FIELDNAME or one of the keywords `AND`, `OR`, `NOT`, `BETWEEN`, `LIKE`,
/// `ORDER`, `BY`, `TRUE`, `FALSE`. The grammar is unambiguous by position
/// except at two places, where the keyword wins: `NOT` at the start of a
/// Condition, and `TRUE`/`FALSE` (the boolean extension) as a Parameter.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    /// An identifier path (escape underscores removed); `escaped` records
    /// that the first component carried an IDL escape underscore, which
    /// makes it a FIELDNAME whatever it spells.
    Word {
        name: String,
        escaped: bool,
    },
    /// INTEGERVALUE within i64
    Integer(i64),
    /// INTEGERVALUE above i64::MAX
    Unsigned(u64),
    /// FLOATVALUE
    Float(f64),
    /// CHARVALUE | STRING | ENUMERATEDVALUE
    Quoted(String),
    /// PARAMETER
    Parameter(usize),
    /// RelOp (`like` arrives as a Word)
    RelOp(Operator),
    LParen,
    RParen,
    Comma,
    Eof,
}

impl Token {
    /// The keyword this token can stand for: an unescaped, undotted word,
    /// upper-cased. Which keyword (if any) applies is the parser's call.
    fn keyword(&self) -> Option<String> {
        match self {
            Token::Word {
                name,
                escaped: false,
            } if !name.contains('.') => Some(name.to_ascii_uppercase()),
            _ => None,
        }
    }

    fn is_keyword(&self, keyword: &str) -> bool {
        self.keyword().as_deref() == Some(keyword)
    }

    /// The boolean extension literal, `TRUE` or `FALSE` in any case.
    fn boolean(&self) -> Option<bool> {
        match self.keyword().as_deref() {
            Some("TRUE") => Some(true),
            Some("FALSE") => Some(false),
            _ => None,
        }
    }

    fn describe(&self) -> String {
        match self {
            Token::Word { name, .. } => match self.boolean() {
                Some(true) => "boolean literal TRUE".to_string(),
                Some(false) => "boolean literal FALSE".to_string(),
                None => format!("'{name}'"),
            },
            Token::Integer(_) | Token::Unsigned(_) => "INTEGERVALUE".to_string(),
            Token::Float(_) => "FLOATVALUE".to_string(),
            Token::Quoted(_) => "quoted literal".to_string(),
            Token::Parameter(n) => format!("PARAMETER %{n}"),
            Token::RelOp(_) => "RelOp".to_string(),
            Token::LParen => "'('".to_string(),
            Token::RParen => "')'".to_string(),
            Token::Comma => "','".to_string(),
            Token::Eof => "end of expression".to_string(),
        }
    }

    /// True for every token that derives Annex B `Parameter` (plus the
    /// boolean extension).
    fn is_parameter(&self) -> bool {
        matches!(
            self,
            Token::Integer(_)
                | Token::Unsigned(_)
                | Token::Float(_)
                | Token::Quoted(_)
                | Token::Parameter(_)
        ) || self.boolean().is_some()
    }
}

/// Largest PARAMETER index: "%n, where n represents a natural number (zero
/// included) smaller than 100" (Annex B, B.2 Token expression).
const MAX_PARAMETER_INDEX: usize = 99;

struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn error(&self, message: impl std::fmt::Display) -> FilterError {
        FilterError::ParseError(format!("{message} (at offset {})", self.pos))
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.input[self.pos..].chars().nth(offset)
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_char(), Some(ch) if ch.is_ascii_whitespace()) {
            self.next_char();
        }
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek_char() == Some(expected) {
            self.next_char();
            true
        } else {
            false
        }
    }

    /// FIELDNAME: IDL identifiers joined by '.'. "The dot '.' is used to
    /// navigate through nested structures. The number of dots that may be
    /// used in a FIELD-NAME is unlimited."
    ///
    /// An IDL identifier (IDL 4.2 7.2.3) is an ASCII letter followed by ASCII
    /// letters, digits and underscores; one leading underscore escapes a
    /// keyword-like spelling and is not part of the name (`_leading` names
    /// the member `leading`). Returns the path with escapes removed and
    /// whether the first component was escaped.
    fn read_field_name(&mut self) -> Result<(String, bool), FilterError> {
        let mut path = String::new();
        let mut first_escaped = false;
        loop {
            let escaped = self.eat('_');
            if path.is_empty() {
                first_escaped = escaped;
            }
            match self.peek_char() {
                Some(ch) if ch.is_ascii_alphabetic() => {}
                Some('_') => {
                    return Err(self.error(
                        "FIELDNAME: an IDL identifier carries at most one escape underscore",
                    ))
                }
                Some(ch) if ch.is_ascii_digit() => {
                    return Err(self.error(
                        "FIELDNAME: an IDL identifier starts with a letter after the optional escape underscore",
                    ))
                }
                Some('.') => return Err(self.error("FIELDNAME: empty path component")),
                _ => return Err(self.error("FIELDNAME: expected an IDL identifier")),
            }
            let start = self.pos;
            while matches!(self.peek_char(), Some(ch) if ch.is_ascii_alphanumeric() || ch == '_') {
                self.next_char();
            }
            path.push_str(&self.input[start..self.pos]);
            if !self.eat('.') {
                break;
            }
            path.push('.');
        }
        match self.peek_char() {
            Some('[') => {
                Err(self.error("FIELDNAME: array index '[' is not defined in DDS 1.4 Annex B"))
            }
            Some(ch) if !ch.is_ascii() => {
                Err(self.error("FIELDNAME: IDL identifiers are ASCII letters, digits and '_'"))
            }
            _ => Ok((path, first_escaped)),
        }
    }

    /// INTEGERVALUE and FLOATVALUE.
    ///
    /// INTEGERVALUE: "Any series of digits, optionally preceded by a plus or
    /// minus sign, representing a decimal integer value within the range of
    /// the system. A hexadecimal number is preceded by 0x and must be a valid
    /// hexadecimal expression."
    ///
    /// FLOATVALUE: "Any series of digits, optionally preceded by a plus or
    /// minus sign and optionally including a floating point ('.'). A
    /// power-of-ten expression may be postfixed, which has the syntax en,
    /// where n is a number, optionally preceded by a plus or minus sign."
    fn read_number(&mut self) -> Result<Token, FilterError> {
        let negative = match self.peek_char() {
            Some('-') => {
                self.next_char();
                true
            }
            Some('+') => {
                self.next_char();
                false
            }
            _ => false,
        };

        let token = if self.peek_char() == Some('0') && matches!(self.peek_at(1), Some('x' | 'X')) {
            self.next_char();
            self.next_char();
            self.read_hexadecimal(negative)?
        } else {
            self.read_decimal(negative)?
        };

        match self.peek_char() {
            Some(ch) if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' => Err(self.error(
                format!("INTEGERVALUE/FLOATVALUE: unexpected '{ch}' after a numeric literal"),
            )),
            _ => Ok(token),
        }
    }

    fn read_hexadecimal(&mut self, negative: bool) -> Result<Token, FilterError> {
        let start = self.pos;
        while matches!(self.peek_char(), Some(ch) if ch.is_ascii_hexdigit()) {
            self.next_char();
        }
        if start == self.pos {
            return Err(self.error("INTEGERVALUE: '0x' must be followed by hexadecimal digits"));
        }
        let magnitude = u64::from_str_radix(&self.input[start..self.pos], 16)
            .map_err(|_| self.error("INTEGERVALUE: hexadecimal literal exceeds 64 bits"))?;
        integer_token(negative, magnitude).map_err(|message| self.error(message))
    }

    fn read_decimal(&mut self, negative: bool) -> Result<Token, FilterError> {
        let int_start = self.pos;
        while matches!(self.peek_char(), Some(ch) if ch.is_ascii_digit()) {
            self.next_char();
        }
        let int_part = &self.input[int_start..self.pos];

        let mut is_float = false;
        let mut frac_part = "";
        if self.eat('.') {
            is_float = true;
            let frac_start = self.pos;
            while matches!(self.peek_char(), Some(ch) if ch.is_ascii_digit()) {
                self.next_char();
            }
            frac_part = &self.input[frac_start..self.pos];
        }
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(self.error("FLOATVALUE: a numeric literal needs at least one digit"));
        }

        let mut exponent = String::from("0");
        if matches!(self.peek_char(), Some('e' | 'E')) {
            is_float = true;
            self.next_char();
            let exp_start = self.pos;
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.next_char();
            }
            let digits_start = self.pos;
            while matches!(self.peek_char(), Some(ch) if ch.is_ascii_digit()) {
                self.next_char();
            }
            if digits_start == self.pos {
                return Err(self.error("FLOATVALUE: the exponent 'e' must be followed by digits"));
            }
            exponent = self.input[exp_start..self.pos].to_string();
        }

        // A digit series without point or exponent is an INTEGERVALUE when
        // it fits i64::MIN..=u64::MAX. Beyond that range it still has a
        // FLOATVALUE derivation (Annex B makes the point and the exponent
        // optional), so it is read as binary64, like `1e19` would be.
        if !is_float {
            if let Ok(token) = int_part
                .parse::<u64>()
                .map_err(|_| ())
                .and_then(|magnitude| integer_token(negative, magnitude).map_err(|_| ()))
            {
                return Ok(token);
            }
        }

        // Normalise to a form every binary64 parser accepts: "<int>.<frac>e<exp>".
        let text = format!(
            "{}{}.{}e{}",
            if negative { "-" } else { "" },
            if int_part.is_empty() { "0" } else { int_part },
            if frac_part.is_empty() { "0" } else { frac_part },
            exponent
        );
        match text.parse::<f64>() {
            Ok(value) if value.is_finite() => Ok(Token::Float(value)),
            _ => Err(self.error("FLOATVALUE: literal does not fit binary64")),
        }
    }

    /// CHARVALUE, STRING and ENUMERATEDVALUE.
    ///
    /// STRING: "Any series of characters encapsulated in single quotes,
    /// except a new-line character or a right quote. A string starts with a
    /// left or right quote, but ends with a right quote." The ASCII left
    /// quote is the grave accent and the right quote is the apostrophe.
    fn read_quoted(&mut self) -> Result<Token, FilterError> {
        self.next_char(); // opening quote, ' or `
        let start = self.pos;
        // CHARVALUE: "A single character enclosed between single quotes".
        // The STRING exclusions (new-line, right quote) do not apply to it,
        // so `'''` is a quoted apostrophe and `'<LF>'` a quoted new-line.
        if matches!(self.peek_char(), Some('\'' | '\n')) && self.peek_at(1) == Some('\'') {
            let ch = self.next_char().unwrap_or('\'');
            self.next_char();
            return Ok(Token::Quoted(ch.to_string()));
        }
        loop {
            match self.peek_char() {
                Some('\'') => {
                    let text = self.input[start..self.pos].to_string();
                    self.next_char();
                    return Ok(Token::Quoted(text));
                }
                Some('\n') => {
                    return Err(
                        self.error("STRING: a new-line character is not allowed inside a literal")
                    )
                }
                Some(_) => {
                    self.next_char();
                }
                None => {
                    return Err(
                        self.error("STRING: unterminated literal, expected a closing right quote")
                    )
                }
            }
        }
    }

    /// PARAMETER: "%n, where n represents a natural number (zero included)
    /// smaller than 100".
    fn read_parameter(&mut self) -> Result<Token, FilterError> {
        self.next_char(); // '%'
        let start = self.pos;
        while matches!(self.peek_char(), Some(ch) if ch.is_ascii_digit()) {
            self.next_char();
        }
        if start == self.pos {
            return Err(self.error("PARAMETER: '%' must be followed by digits"));
        }
        let text = &self.input[start..self.pos];
        match text.parse::<usize>() {
            Ok(index) if index <= MAX_PARAMETER_INDEX => Ok(Token::Parameter(index)),
            _ => Err(self.error(format!(
                "PARAMETER: %{text} is outside the Annex B range %0..%{MAX_PARAMETER_INDEX}"
            ))),
        }
    }

    fn next_token(&mut self) -> Result<Token, FilterError> {
        self.skip_whitespace();

        let ch = match self.peek_char() {
            Some(c) => c,
            None => return Ok(Token::Eof),
        };

        match ch {
            '>' => {
                self.next_char();
                Ok(Token::RelOp(if self.eat('=') {
                    Operator::Ge
                } else {
                    Operator::Gt
                }))
            }
            '<' => {
                self.next_char();
                Ok(Token::RelOp(if self.eat('=') {
                    Operator::Le
                } else if self.eat('>') {
                    Operator::Ne
                } else {
                    Operator::Lt
                }))
            }
            // Local aliases (not Annex B RelOp, documented in 1.4.6): '=='
            // is '=' and '!=' is '<>'. The canonical rendering emits the
            // Annex B spelling, so the alias never leaves the process.
            '=' => {
                self.next_char();
                self.eat('=');
                Ok(Token::RelOp(Operator::Eq))
            }
            '!' => {
                self.next_char();
                if self.eat('=') {
                    return Ok(Token::RelOp(Operator::Ne));
                }
                Err(self.error("RelOp: '!' is only valid in the alias '!='"))
            }
            '(' => {
                self.next_char();
                Ok(Token::LParen)
            }
            ')' => {
                self.next_char();
                Ok(Token::RParen)
            }
            ',' => {
                self.next_char();
                Ok(Token::Comma)
            }
            '%' => self.read_parameter(),
            '\'' | '`' => self.read_quoted(),
            '"' => Err(self.error(
                "STRING: double quotes are not Annex B string delimiters, use single quotes",
            )),
            '0'..='9' => self.read_number(),
            '.' if matches!(self.peek_at(1), Some(c) if c.is_ascii_digit()) => self.read_number(),
            '.' => Err(self
                .error("FIELDNAME/FLOATVALUE: '.' must follow an identifier or precede a digit")),
            '+' | '-' => {
                let next = self.peek_at(1);
                let starts_number = matches!(next, Some(c) if c.is_ascii_digit())
                    || (next == Some('.')
                        && matches!(self.peek_at(2), Some(c) if c.is_ascii_digit()));
                if starts_number {
                    self.read_number()
                } else {
                    Err(self.error(format!(
                        "INTEGERVALUE/FLOATVALUE: the sign '{ch}' must be immediately followed by digits"
                    )))
                }
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let (name, escaped) = self.read_field_name()?;
                Ok(Token::Word { name, escaped })
            }
            c if c.is_alphabetic() => {
                Err(self.error("FIELDNAME: IDL identifiers are ASCII letters, digits and '_'"))
            }
            _ => Err(self.error(format!("unexpected character '{ch}'"))),
        }
    }
}

/// Build the INTEGERVALUE token for a sign and a magnitude. Negative values
/// must fit i64; positive values above i64::MAX are carried as u64.
fn integer_token(negative: bool, magnitude: u64) -> Result<Token, &'static str> {
    if negative {
        let value = i128::from(magnitude).checked_neg().unwrap_or(i128::MIN);
        i64::try_from(value)
            .map(Token::Integer)
            .map_err(|_| "INTEGERVALUE: negative literal below i64::MIN")
    } else {
        Ok(match i64::try_from(magnitude) {
            Ok(value) => Token::Integer(value),
            Err(_) => Token::Unsigned(magnitude),
        })
    }
}

/// Deepest nesting of parentheses and `NOT` accepted in one expression.
///
/// Nesting is the only source of recursion left in the parser, the renderer,
/// the validator, the evaluator and the destructor (AND/OR chains are flat
/// vectors), so this bounds the stack of all five walks. 64 levels cost well
/// under 100 KiB of stack in debug builds against a 1 MiB minimum thread
/// stack; no real filter comes near it.
pub const MAX_NESTING_DEPTH: usize = 64;

/// Largest number of predicates and connectives accepted in one expression.
///
/// 65535 is the u16 parameter length of an RTPS ContentFilterProperty: an
/// expression with more nodes than that cannot even be announced.
pub const MAX_NODE_COUNT: usize = 65_535;

/// Recursive-descent parser over the Annex B `Condition` grammar.
///
/// The BNF leaves the precedence of `AND`, `OR` and `NOT` open; this parser
/// applies the SQL convention `NOT` > `AND` > `OR`, with parentheses
/// overriding it.
struct Parser<'a> {
    lexer: Lexer<'a>,
    current: Token,
    /// Current nesting of parentheses and NOT.
    depth: usize,
    /// Nodes created so far.
    nodes: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, FilterError> {
        let mut lexer = Lexer::new(input);
        let current = lexer.next_token()?;
        Ok(Self {
            lexer,
            current,
            depth: 0,
            nodes: 0,
        })
    }

    /// Enter one nesting level (a parenthesis or a NOT).
    fn descend(&mut self) -> Result<(), FilterError> {
        if self.depth == MAX_NESTING_DEPTH {
            return Err(FilterError::ParseError(format!(
                "Condition: nesting deeper than {MAX_NESTING_DEPTH} levels of parentheses or NOT (at offset {})",
                self.lexer.pos
            )));
        }
        self.depth += 1;
        Ok(())
    }

    fn ascend(&mut self) {
        self.depth -= 1;
    }

    /// Account for one more node in the tree.
    fn node(&mut self) -> Result<(), FilterError> {
        if self.nodes == MAX_NODE_COUNT {
            return Err(FilterError::ParseError(format!(
                "Condition: more than {MAX_NODE_COUNT} predicates and connectives (at offset {})",
                self.lexer.pos
            )));
        }
        self.nodes += 1;
        Ok(())
    }

    fn error(&self, message: impl std::fmt::Display) -> FilterError {
        FilterError::ParseError(format!(
            "{message}, got {} (at offset {})",
            self.current.describe(),
            self.lexer.pos
        ))
    }

    fn advance(&mut self) -> Result<(), FilterError> {
        self.current = self.lexer.next_token()?;
        Ok(())
    }

    /// `Condition ::= Condition 'OR' Condition | ...`, collected flat.
    fn parse_condition(&mut self) -> Result<Expression, FilterError> {
        let first = self.parse_and()?;
        if !self.current.is_keyword("OR") {
            return Ok(first);
        }
        self.node()?;
        let mut items = vec![first];
        while self.current.is_keyword("OR") {
            self.advance()?;
            items.push(self.parse_and()?);
        }
        Ok(Expression::Or(items))
    }

    /// `Condition ::= Condition 'AND' Condition | ...`, collected flat.
    fn parse_and(&mut self) -> Result<Expression, FilterError> {
        let first = self.parse_not()?;
        if !self.current.is_keyword("AND") {
            return Ok(first);
        }
        self.node()?;
        let mut items = vec![first];
        while self.current.is_keyword("AND") {
            self.advance()?;
            items.push(self.parse_not()?);
        }
        Ok(Expression::And(items))
    }

    /// `Condition ::= 'NOT' Condition | ...`. A word spelling NOT at the
    /// start of a Condition is the keyword (the one ambiguity of the BNF
    /// resolved in favour of the keyword; write `_not` for a member named
    /// `not`).
    fn parse_not(&mut self) -> Result<Expression, FilterError> {
        if self.current.is_keyword("NOT") {
            self.node()?;
            self.descend()?;
            self.advance()?;
            let inner = self.parse_not()?;
            self.ascend();
            return Ok(Expression::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    /// `Condition ::= '(' Condition ')' | Predicate`
    fn parse_primary(&mut self) -> Result<Expression, FilterError> {
        if self.current == Token::LParen {
            self.descend()?;
            self.advance()?;
            let inner = self.parse_condition()?;
            if self.current != Token::RParen {
                return Err(self.error("Condition: expected ')' to close '('"));
            }
            self.advance()?;
            self.ascend();
            return Ok(inner);
        }
        self.node()?;
        self.parse_predicate()
    }

    /// The RelOp the current token stands for, `like` included.
    fn rel_op(&self) -> Option<Operator> {
        match &self.current {
            Token::RelOp(op) => Some(*op),
            token if token.is_keyword("LIKE") => Some(Operator::Like),
            _ => None,
        }
    }

    /// True when the current token is a FIELDNAME at this position: any word
    /// but the boolean extension literals.
    fn at_field_name(&self) -> bool {
        matches!(self.current, Token::Word { .. }) && self.current.boolean().is_none()
    }

    /// `Predicate ::= ComparisonPredicate | BetweenPredicate`
    fn parse_predicate(&mut self) -> Result<Expression, FilterError> {
        if self.at_field_name() {
            let Token::Word { name, .. } = &self.current else {
                unreachable!("at_field_name checked the variant")
            };
            let field = name.clone();
            self.advance()?;
            // BetweenPredicate ::= FIELDNAME 'BETWEEN' Range
            if self.current.is_keyword("BETWEEN") {
                self.advance()?;
                let (low, high) = self.parse_range()?;
                return Ok(Expression::Between {
                    field,
                    low,
                    high,
                    negated: false,
                });
            }
            // BetweenPredicate ::= FIELDNAME 'NOT BETWEEN' Range
            if self.current.is_keyword("NOT") {
                self.advance()?;
                if !self.current.is_keyword("BETWEEN") {
                    return Err(self.error(
                        "BetweenPredicate: expected 'BETWEEN' after 'NOT' (NOT LIKE is not an Annex B production)",
                    ));
                }
                self.advance()?;
                let (low, high) = self.parse_range()?;
                return Ok(Expression::Between {
                    field,
                    low,
                    high,
                    negated: true,
                });
            }
            // ComparisonPredicate ::= FIELDNAME RelOp Parameter
            //                       | FIELDNAME RelOp FIELDNAME
            let Some(op) = self.rel_op() else {
                return Err(
                    self.error("Predicate: expected a RelOp or 'BETWEEN' after the FIELDNAME")
                );
            };
            self.advance()?;
            let right = self.parse_operand()?;
            return Ok(Expression::Comparison {
                left: Value::Field(field),
                op,
                right,
            });
        }

        if self.current.is_parameter() {
            let left = self.parse_operand()?;
            // ComparisonPredicate ::= Parameter RelOp FIELDNAME
            if self.current.is_keyword("BETWEEN") {
                return Err(self.error("BetweenPredicate: the left side must be a FIELDNAME"));
            }
            let Some(op) = self.rel_op() else {
                return Err(self.error("ComparisonPredicate: expected a RelOp after the Parameter"));
            };
            self.advance()?;
            if !self.at_field_name() {
                return Err(self.error(
                    "ComparisonPredicate: at least one side must be a FIELDNAME (Annex B has no 'Parameter RelOp Parameter' production)",
                ));
            }
            let right = self.parse_operand()?;
            return Ok(Expression::Comparison { left, op, right });
        }

        Err(self.error("Condition: expected a Predicate"))
    }

    /// `Range ::= Parameter 'AND' Parameter`
    fn parse_range(&mut self) -> Result<(Value, Value), FilterError> {
        let low = self.parse_bound()?;
        if !self.current.is_keyword("AND") {
            return Err(self.error("Range: expected 'AND' between the two bounds"));
        }
        self.advance()?;
        let high = self.parse_bound()?;
        Ok((low, high))
    }

    fn parse_bound(&mut self) -> Result<Value, FilterError> {
        // The boolean extension is a ComparisonPredicate Parameter only; a
        // boolean has no order, so a Range bound cannot be one.
        if self.current.boolean().is_some() {
            return Err(self.error(
                "Range: a bound must be an Annex B Parameter; the boolean literals TRUE/FALSE are not accepted here",
            ));
        }
        if !self.current.is_parameter() {
            return Err(self.error(
                "Range: each bound must be a Parameter (a literal or %n), not a FIELDNAME",
            ));
        }
        self.parse_operand()
    }

    /// One `Parameter` token or one `FIELDNAME`.
    fn parse_operand(&mut self) -> Result<Value, FilterError> {
        let value = match &self.current {
            Token::Word { name, .. } => match self.current.boolean() {
                Some(b) => Value::Boolean(b),
                None => Value::Field(name.clone()),
            },
            Token::Integer(n) => Value::Integer(*n),
            Token::Unsigned(n) => Value::Unsigned(*n),
            Token::Float(f) => Value::Float(*f),
            Token::Quoted(s) => Value::String(s.clone()),
            Token::Parameter(idx) => Value::Parameter(*idx),
            _ => return Err(self.error("ComparisonPredicate: expected a Parameter or a FIELDNAME")),
        };
        self.advance()?;
        Ok(value)
    }

    /// `'ORDER BY' (FIELDNAME // ',')`
    fn parse_order_by(&mut self) -> Result<Vec<String>, FilterError> {
        self.advance()?; // ORDER
        if !self.current.is_keyword("BY") {
            return Err(self.error("QueryExpression: expected 'BY' after 'ORDER'"));
        }
        let mut fields = Vec::new();
        loop {
            self.advance()?; // BY or ','
            match &self.current {
                Token::Word { name, .. } => fields.push(name.clone()),
                _ => {
                    return Err(self.error(
                        "QueryExpression: 'ORDER BY' takes a comma-separated list of FIELDNAMEs",
                    ))
                }
            }
            self.advance()?;
            if self.current != Token::Comma {
                break;
            }
        }
        Ok(fields)
    }

    fn expect_end(&self) -> Result<(), FilterError> {
        if self.current == Token::Eof {
            Ok(())
        } else if self.current.is_keyword("ORDER") {
            Err(self.error("FilterExpression: 'ORDER BY' belongs to a QueryExpression only"))
        } else {
            Err(self.error("Condition: unexpected trailing input after a complete expression"))
        }
    }
}

/// Parse a `FilterExpression ::= Condition` (Annex B, B.2).
///
/// This is the syntax of a ContentFilteredTopic `filter_expression`. An empty
/// or blank string is `FilterError::EmptyExpression`; see
/// [`parse_query_expression`] for the QueryCondition syntax, where the
/// condition is optional.
///
/// # Example
///
/// ```ignore
/// let expr = parse_expression("temperature > 25.0 AND humidity < 80")?;
/// ```
pub fn parse_expression(expression: &str) -> Result<Expression, FilterError> {
    if expression.trim().is_empty() {
        return Err(FilterError::EmptyExpression);
    }
    let mut parser = Parser::new(expression)?;
    let condition = parser.parse_condition()?;
    parser.expect_end()?;
    Ok(condition)
}

/// Parse a `QueryExpression ::= {Condition}{'ORDER BY' (FIELDNAME // ',')}`
/// (Annex B, B.2).
///
/// This is the syntax of a QueryCondition `query_expression`. Both parts are
/// optional: an empty string is a valid query that matches every sample.
pub fn parse_query_expression(expression: &str) -> Result<QueryExpression, FilterError> {
    let mut parser = Parser::new(expression)?;
    let condition = if parser.current == Token::Eof || parser.current.is_keyword("ORDER") {
        None
    } else {
        Some(parser.parse_condition()?)
    };
    let order_by = if parser.current.is_keyword("ORDER") {
        parser.parse_order_by()?
    } else {
        Vec::new()
    };
    if parser.current != Token::Eof {
        return Err(parser.error("QueryExpression: unexpected trailing input"));
    }
    Ok(QueryExpression {
        condition,
        order_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_numeric_literals_and_trailing_input_are_rejected() {
        for expression in ["value = 1 garbage", "value = 1)", "value", "0"] {
            assert!(parse_expression(expression).is_err(), "{expression}");
        }
        assert!(parse_expression("value = -9223372036854775808").is_ok());
        assert!(parse_expression("value = 18446744073709551615").is_ok());
        // Beyond the integer range a digit series is a FLOATVALUE (binary64).
        for (expression, expected) in [
            ("value = 18446744073709551616", 18_446_744_073_709_551_616.0),
            ("value = -9223372036854775809", -9_223_372_036_854_775_809.0),
        ] {
            match parse_expression(expression) {
                Ok(Expression::Comparison { right, .. }) => {
                    assert_eq!(right, Value::Float(expected), "{expression}")
                }
                other => panic!("{expression}: {other:?}"),
            }
        }
        assert!(parse_expression("value = 0x1FFFFFFFFFFFFFFFF").is_err());
        assert!(parse_expression("value = 1e3 AND enabled = 1").is_ok());
        assert!(parse_expression("(value = 1) AND (enabled = TRUE)").is_ok());
    }

    #[test]
    fn test_parse_simple_comparison() {
        let expr = parse_expression("temperature > 25").unwrap();
        match expr {
            Expression::Comparison { left, op, right } => {
                assert_eq!(left, Value::Field("temperature".to_string()));
                assert_eq!(op, Operator::Gt);
                assert_eq!(right, Value::Integer(25));
            }
            _ => panic!("Expected comparison"),
        }
    }

    #[test]
    fn test_parse_float_comparison() {
        let pi = std::f64::consts::PI;
        let expr = parse_expression(&format!("value >= {pi}")).unwrap();
        match expr {
            Expression::Comparison { left, op, right } => {
                assert_eq!(left, Value::Field("value".to_string()));
                assert_eq!(op, Operator::Ge);
                assert!(matches!(right, Value::Float(f) if (f - pi).abs() < 0.001));
            }
            _ => panic!("Expected comparison"),
        }
    }

    #[test]
    fn numeric_literal_forms_round_trip_exactly() {
        for (expression, expected) in [
            ("x = 0x1F", Value::Integer(31)),
            ("x = -0x10", Value::Integer(-16)),
            ("x = 0xFFFFFFFFFFFFFFFF", Value::Unsigned(u64::MAX)),
            ("x = -0x8000000000000000", Value::Integer(i64::MIN)),
            ("x = +42", Value::Integer(42)),
            ("x = 1e3", Value::Float(1000.0)),
            ("x = 1.", Value::Float(1.0)),
            ("x = .5", Value::Float(0.5)),
            ("x = -.5E1", Value::Float(-5.0)),
            ("x = 1.e2", Value::Float(100.0)),
        ] {
            match parse_expression(expression) {
                Ok(Expression::Comparison { right, .. }) => {
                    assert_eq!(right, expected, "{expression}")
                }
                other => panic!("{expression}: {other:?}"),
            }
        }
        assert!(parse_expression("x = -0x8000000000000001").is_err());
    }

    #[test]
    fn test_parse_parameter() {
        let expr = parse_expression("x > %0").unwrap();
        match expr {
            Expression::Comparison { right, .. } => {
                assert_eq!(right, Value::Parameter(0));
            }
            _ => panic!("Expected comparison"),
        }
    }

    #[test]
    fn test_parse_string_literal() {
        let expr = parse_expression("name = 'hello'").unwrap();
        match expr {
            Expression::Comparison { right, .. } => {
                assert_eq!(right, Value::String("hello".to_string()));
            }
            _ => panic!("Expected comparison"),
        }
    }

    #[test]
    fn between_predicate_builds_inclusive_range_node() {
        assert_eq!(
            parse_expression("pos.x NOT BETWEEN %0 AND 'z'").unwrap(),
            Expression::Between {
                field: "pos.x".to_string(),
                low: Value::Parameter(0),
                high: Value::String("z".to_string()),
                negated: true,
            }
        );
    }

    #[test]
    fn test_parse_and() {
        let expr = parse_expression("a > 1 AND b < 2").unwrap();
        assert!(matches!(expr, Expression::And(_)));
    }

    #[test]
    fn test_parse_or() {
        let expr = parse_expression("a > 1 OR b < 2").unwrap();
        assert!(matches!(expr, Expression::Or(_)));
    }

    #[test]
    fn test_parse_not() {
        let expr = parse_expression("NOT a > 1").unwrap();
        assert!(matches!(expr, Expression::Not(_)));
    }

    #[test]
    fn test_parse_parentheses() {
        let expr = parse_expression("(a > 1 OR b < 2) AND c = 3").unwrap();
        assert!(matches!(expr, Expression::And(_)));
    }

    #[test]
    fn test_parse_complex() {
        let expr = parse_expression("temperature > %0 AND humidity < %1 OR emergency = 1").unwrap();
        // Should parse as: (temp > %0 AND humidity < %1) OR emergency = 1
        assert!(matches!(expr, Expression::Or(_)));
    }

    #[test]
    fn test_parse_operators() {
        assert!(parse_expression("x > 1").is_ok());
        assert!(parse_expression("x < 1").is_ok());
        assert!(parse_expression("x >= 1").is_ok());
        assert!(parse_expression("x <= 1").is_ok());
        assert!(parse_expression("x = 1").is_ok());
        assert!(parse_expression("x <> 1").is_ok());
        // Local aliases: parsed as the Annex B operator they stand for.
        assert_eq!(parse_expression("x == 1"), parse_expression("x = 1"));
        assert_eq!(parse_expression("x != 1"), parse_expression("x <> 1"));
        assert!(parse_expression("x ! 1").is_err());
    }

    #[test]
    fn canonical_rendering_round_trips_and_uses_annex_b_spellings() {
        for (source, canonical) in [
            ("x != 3", "x <> 3"),
            ("x == 3 and y!=4", "x = 3 AND y <> 4"),
            (
                "not x = 1 or y = 2 and z = 3",
                "NOT x = 1 OR y = 2 AND z = 3",
            ),
            ("(x = 1 OR y = 2) AND z = 3", "(x = 1 OR y = 2) AND z = 3"),
            ("x = 1 AND (y = 2 AND z = 3)", "x = 1 AND (y = 2 AND z = 3)"),
            ("NOT (x = 1 AND y = 2)", "NOT (x = 1 AND y = 2)"),
            ("NOT NOT x = 1", "NOT NOT x = 1"),
            ("((x = 1))", "x = 1"),
            (
                "pos.x not between 0x0A and 1e1",
                "pos.x NOT BETWEEN 10 AND 10.0",
            ),
            ("name like `a%'", "name LIKE 'a%'"),
            ("f = -.5E1", "f = -5.0"),
            ("u = 0xFFFFFFFFFFFFFFFF", "u = 18446744073709551615"),
            ("flag = true", "flag = TRUE"),
            ("%7 <= x", "%7 <= x"),
            ("c = '''", "c = '''"),
            ("c = '\n'", "c = '\n'"),
            // IDL escapes: stripped for the lookup, re-emitted for a
            // component that spells a keyword, so `not`/`true` round-trip.
            ("_leading = 1", "leading = 1"),
            ("_not = 1 AND order = 2", "_not = 1 AND _order = 2"),
            ("x = _true", "x = _true"),
            ("pos._by.x = 1", "pos._by.x = 1"),
            ("_not BETWEEN 1 AND 2", "_not BETWEEN 1 AND 2"),
        ] {
            let parsed = parse_expression(source).unwrap();
            assert_eq!(parsed.to_string(), canonical, "{source}");
            assert_eq!(
                parse_expression(&parsed.to_string()).unwrap(),
                parsed,
                "round trip of {source}"
            );
        }
        let query = parse_query_expression("x != 1 order by pos.x, y").unwrap();
        assert_eq!(query.to_string(), "x <> 1 ORDER BY pos.x, y");
        assert_eq!(parse_query_expression("").unwrap().to_string(), "");
    }

    #[test]
    fn errors_name_the_annex_b_rule() {
        for (expression, needle) in [
            ("x ! 1", "RelOp"),
            ("x = %100", "PARAMETER"),
            ("x = 0x", "INTEGERVALUE"),
            ("x = 1e", "FLOATVALUE"),
            ("a[0] = 1", "FIELDNAME"),
            ("name = \"a\"", "STRING"),
            ("1 = 1", "ComparisonPredicate"),
            ("x BETWEEN y AND 1", "Range"),
            ("x = 1 ORDER BY x", "QueryExpression"),
        ] {
            match parse_expression(expression) {
                Err(FilterError::ParseError(message)) => {
                    assert!(message.contains(needle), "{expression}: {message}")
                }
                other => panic!("{expression}: {other:?}"),
            }
        }
    }

    #[test]
    fn query_expression_accepts_optional_condition_and_order_by() {
        for (expression, condition, order_by) in [
            ("", false, vec![]),
            ("   ", false, vec![]),
            ("x = 1", true, vec![]),
            ("ORDER BY x", false, vec!["x"]),
            ("order by pos.x, y", false, vec!["pos.x", "y"]),
            ("x = 1 ORDER BY x", true, vec!["x"]),
            (
                "x = 1 AND y = 2 ORDER BY y, x, z",
                true,
                vec!["y", "x", "z"],
            ),
        ] {
            let parsed = parse_query_expression(expression).unwrap();
            assert_eq!(parsed.condition.is_some(), condition, "{expression}");
            assert_eq!(parsed.order_by, order_by, "{expression}");
        }
        for expression in [
            "x = 1 ORDER BY",
            "ORDER x",
            "x = 1 ORDER BY 1",
            "x = 1 ORDER BY x,",
            "ORDER BY x ORDER BY y",
            "x = 1 ORDER BY x DESC",
            "x = 1;",
            "ORDER BY",
        ] {
            assert!(parse_query_expression(expression).is_err(), "{expression}");
        }
    }

    #[test]
    fn test_parse_error_empty() {
        assert!(matches!(
            parse_expression(""),
            Err(FilterError::EmptyExpression)
        ));
    }

    #[test]
    fn test_parse_error_invalid() {
        assert!(parse_expression("@@invalid").is_err());
    }
}
