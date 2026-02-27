// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Filter Expression Parser
//!
//! Parses SQL-like filter expressions into an AST.

use super::FilterError;

/// Comparison operators supported in filter expressions.
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
    /// Equal (= or ==)
    Eq,
    /// Not equal (<> or !=)
    Ne,
    /// LIKE pattern matching
    Like,
}

/// Value in a filter expression (literal, parameter, or field reference).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Integer literal
    Integer(i64),
    /// Float literal
    Float(f64),
    /// String literal
    String(String),
    /// Boolean literal
    Boolean(bool),
    /// Parameter reference (%0, %1, etc.)
    Parameter(usize),
    /// Field name reference
    Field(String),
}

/// Parsed filter expression AST node.
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// Comparison: field op value
    Comparison {
        left: Value,
        op: Operator,
        right: Value,
    },
    /// Logical AND
    And(Box<Expression>, Box<Expression>),
    /// Logical OR
    Or(Box<Expression>, Box<Expression>),
    /// Logical NOT
    Not(Box<Expression>),
    /// Always true (matches everything)
    True,
}

/// Token types for the lexer.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    Identifier(String),
    Integer(i64),
    Float(f64),
    String(String),
    Parameter(usize),
    Operator(Operator),
    And,
    Or,
    Not,
    LParen,
    RParen,
    Eof,
}

struct Lexer<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.next_char();
            } else {
                break;
            }
        }
    }

    fn read_identifier(&mut self) -> String {
        let start = self.pos;
        while let Some(ch) = self.peek_char() {
            if ch.is_alphanumeric() || ch == '_' {
                self.next_char();
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_string()
    }

    fn read_number(&mut self) -> Token {
        let start = self.pos;
        let mut has_dot = false;

        // Handle negative numbers
        if self.peek_char() == Some('-') {
            self.next_char();
        }

        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_digit() {
                self.next_char();
            } else if ch == '.' && !has_dot {
                has_dot = true;
                self.next_char();
            } else {
                break;
            }
        }

        let num_str = &self.input[start..self.pos];
        if has_dot {
            Token::Float(num_str.parse().unwrap_or(0.0))
        } else {
            Token::Integer(num_str.parse().unwrap_or(0))
        }
    }

    fn read_string(&mut self) -> Result<String, FilterError> {
        #[allow(clippy::unwrap_used)] // caller verified peek_char returned a quote character
        let quote = self.next_char().unwrap(); // consume opening quote
        let start = self.pos;

        while let Some(ch) = self.peek_char() {
            if ch == quote {
                let s = self.input[start..self.pos].to_string();
                self.next_char(); // consume closing quote
                return Ok(s);
            }
            self.next_char();
        }

        Err(FilterError::ParseError("Unterminated string".to_string()))
    }

    fn read_parameter(&mut self) -> Result<Token, FilterError> {
        self.next_char(); // consume '%'
        let start = self.pos;

        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_digit() {
                self.next_char();
            } else {
                break;
            }
        }

        if start == self.pos {
            return Err(FilterError::ParseError(
                "Expected digit after '%'".to_string(),
            ));
        }

        let idx: usize = self.input[start..self.pos]
            .parse()
            .map_err(|_| FilterError::ParseError("Invalid parameter index".to_string()))?;

        Ok(Token::Parameter(idx))
    }

    fn next_token(&mut self) -> Result<Token, FilterError> {
        self.skip_whitespace();

        let ch = match self.peek_char() {
            Some(c) => c,
            None => return Ok(Token::Eof),
        };

        // Operators (check multi-char first)
        if ch == '>' {
            self.next_char();
            if self.peek_char() == Some('=') {
                self.next_char();
                return Ok(Token::Operator(Operator::Ge));
            }
            return Ok(Token::Operator(Operator::Gt));
        }

        if ch == '<' {
            self.next_char();
            if self.peek_char() == Some('=') {
                self.next_char();
                return Ok(Token::Operator(Operator::Le));
            }
            if self.peek_char() == Some('>') {
                self.next_char();
                return Ok(Token::Operator(Operator::Ne));
            }
            return Ok(Token::Operator(Operator::Lt));
        }

        if ch == '=' {
            self.next_char();
            if self.peek_char() == Some('=') {
                self.next_char();
            }
            return Ok(Token::Operator(Operator::Eq));
        }

        if ch == '!' {
            self.next_char();
            if self.peek_char() == Some('=') {
                self.next_char();
                return Ok(Token::Operator(Operator::Ne));
            }
            return Err(FilterError::ParseError(
                "Expected '=' after '!'".to_string(),
            ));
        }

        // Parentheses
        if ch == '(' {
            self.next_char();
            return Ok(Token::LParen);
        }
        if ch == ')' {
            self.next_char();
            return Ok(Token::RParen);
        }

        // Parameter
        if ch == '%' {
            return self.read_parameter();
        }

        // String literal
        if ch == '\'' || ch == '"' {
            let s = self.read_string()?;
            return Ok(Token::String(s));
        }

        // Number (including negative)
        if ch.is_ascii_digit()
            || (ch == '-' && self.input[self.pos + 1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            return Ok(self.read_number());
        }

        // Identifier or keyword
        if ch.is_alphabetic() || ch == '_' {
            let ident = self.read_identifier();
            let upper = ident.to_uppercase();

            return Ok(match upper.as_str() {
                "AND" => Token::And,
                "OR" => Token::Or,
                "NOT" => Token::Not,
                "TRUE" => Token::Integer(1), // Treat as truthy
                "FALSE" => Token::Integer(0),
                "LIKE" => Token::Operator(Operator::Like),
                _ => Token::Identifier(ident),
            });
        }

        Err(FilterError::ParseError(format!(
            "Unexpected character: '{}'",
            ch
        )))
    }
}

/// Parser for filter expressions.
struct Parser<'a> {
    lexer: Lexer<'a>,
    current: Token,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Result<Self, FilterError> {
        let mut lexer = Lexer::new(input);
        let current = lexer.next_token()?;
        Ok(Self { lexer, current })
    }

    fn advance(&mut self) -> Result<(), FilterError> {
        self.current = self.lexer.next_token()?;
        Ok(())
    }

    fn parse_expression(&mut self) -> Result<Expression, FilterError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expression, FilterError> {
        let mut left = self.parse_and()?;

        while self.current == Token::Or {
            self.advance()?;
            let right = self.parse_and()?;
            left = Expression::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expression, FilterError> {
        let mut left = self.parse_not()?;

        while self.current == Token::And {
            self.advance()?;
            let right = self.parse_not()?;
            left = Expression::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expression, FilterError> {
        if self.current == Token::Not {
            self.advance()?;
            let expr = self.parse_not()?;
            return Ok(Expression::Not(Box::new(expr)));
        }

        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expression, FilterError> {
        // Parenthesized expression
        if self.current == Token::LParen {
            self.advance()?;
            let expr = self.parse_expression()?;
            if self.current != Token::RParen {
                return Err(FilterError::ParseError(
                    "Expected closing parenthesis".to_string(),
                ));
            }
            self.advance()?;
            return Ok(expr);
        }

        // Comparison: value op value
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<Expression, FilterError> {
        let left = self.parse_value()?;

        // Get operator
        let op = match &self.current {
            Token::Operator(op) => *op,
            Token::Eof => return Ok(Expression::True), // No comparison, just a value
            _ => {
                return Err(FilterError::ParseError(format!(
                    "Expected operator, got {:?}",
                    self.current
                )))
            }
        };

        self.advance()?;

        let right = self.parse_value()?;

        Ok(Expression::Comparison { left, op, right })
    }

    fn parse_value(&mut self) -> Result<Value, FilterError> {
        let value = match &self.current {
            Token::Identifier(name) => Value::Field(name.clone()),
            Token::Integer(n) => Value::Integer(*n),
            Token::Float(f) => Value::Float(*f),
            Token::String(s) => Value::String(s.clone()),
            Token::Parameter(idx) => Value::Parameter(*idx),
            _ => {
                return Err(FilterError::ParseError(format!(
                    "Expected value, got {:?}",
                    self.current
                )))
            }
        };

        self.advance()?;
        Ok(value)
    }
}

/// Parse a filter expression string into an AST.
///
/// # Arguments
///
/// * `expression` - SQL-like filter expression
///
/// # Returns
///
/// Returns the parsed Expression AST or a FilterError.
///
/// # Example
///
/// ```ignore
/// let expr = parse_expression("temperature > 25.0 AND humidity < 80")?;
/// ```
pub fn parse_expression(expression: &str) -> Result<Expression, FilterError> {
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return Err(FilterError::EmptyExpression);
    }

    let mut parser = Parser::new(trimmed)?;
    parser.parse_expression()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_parse_and() {
        let expr = parse_expression("a > 1 AND b < 2").unwrap();
        assert!(matches!(expr, Expression::And(_, _)));
    }

    #[test]
    fn test_parse_or() {
        let expr = parse_expression("a > 1 OR b < 2").unwrap();
        assert!(matches!(expr, Expression::Or(_, _)));
    }

    #[test]
    fn test_parse_not() {
        let expr = parse_expression("NOT a > 1").unwrap();
        assert!(matches!(expr, Expression::Not(_)));
    }

    #[test]
    fn test_parse_parentheses() {
        let expr = parse_expression("(a > 1 OR b < 2) AND c = 3").unwrap();
        assert!(matches!(expr, Expression::And(_, _)));
    }

    #[test]
    fn test_parse_complex() {
        let expr = parse_expression("temperature > %0 AND humidity < %1 OR emergency = 1").unwrap();
        // Should parse as: (temp > %0 AND humidity < %1) OR emergency = 1
        assert!(matches!(expr, Expression::Or(_, _)));
    }

    #[test]
    fn test_parse_operators() {
        assert!(parse_expression("x > 1").is_ok());
        assert!(parse_expression("x < 1").is_ok());
        assert!(parse_expression("x >= 1").is_ok());
        assert!(parse_expression("x <= 1").is_ok());
        assert!(parse_expression("x = 1").is_ok());
        assert!(parse_expression("x == 1").is_ok());
        assert!(parse_expression("x <> 1").is_ok());
        assert!(parse_expression("x != 1").is_ok());
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
