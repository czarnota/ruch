use std::env;
use std::error::Error;
use std::io;
use std::io::Write;
use std::fmt;

/// Check if `s` is a valid hexadecimal byte string.
fn valid_hex_str(s: &str) -> bool {
    if s.is_empty() {
        false
    } else if !s.starts_with("0x") {
        false
    } else if s.len() < 3 {
        false
    } else {
        s[2..].chars().all(|c| matches!(c, 'a'..='f' | 'A'..='F' | '0'..='9'))
    }
}

/// Check if `s` is a valid binary string.
fn valid_binary_str(s: &str) -> bool {
    if s.is_empty() {
        false
    } else if !s.starts_with("0b") {
        false
    } else if s.len() < 3 {
        false
    } else {
        s[2..].chars().all(|c| c == '0' || c == '1')
    }
}

fn bit_set(data: &mut Vec<u8>, bit_no: usize, value: bool) {
    let byte = bit_no / 8;
    if byte >= data.len() {
        data.resize(byte + 1, 0);
    }

    let bit = bit_no % 8;
    if value {
        data[byte] |= 1 << bit;
    } else {
        data[byte] &= !(1 << bit);
    }
}

fn strlpad(s: &str, min_len: usize, with: char) -> String
{
    if s.len() < min_len {
        (s.len()..min_len).map(|x| with).collect::<String>() + s
    } else {
        String::from(s)
    }
}

fn strrpad(s: &str, min_len: usize, with: char) -> String
{
    if s.len() < min_len {
        String::from(s) + &(s.len()..min_len).map(|x| with).collect::<String>()
    } else {
        String::from(s)
    }
}

struct Packet {
    bytes: Vec<u8>,
}

impl Packet {
    fn from_byte_str(byte_str: &str) -> Result<Self, &'static str> {
        let v: Vec<_> = byte_str.split_whitespace().collect();

        let mut bytes : Vec<u8> = Vec::new();

        let mut i: usize = 0;

        for token in v {
            if valid_binary_str(token) {
                let token = &token[2..];
                for c in token.chars() {
                    let digit = c.to_digit(2).unwrap();
                    let bit = (i/8) * 8 + 7 - i % 8;
                    bit_set(&mut bytes, bit, digit != 0);
                    i += 1;
                }
            } else if valid_hex_str(token) {
                let token = &token[2..];

                for c in token.chars() {
                    let digit = c.to_digit(16).unwrap();
                    for j in (0..4).rev() {
                        let bit = (i/8) * 8 + 7 - i % 8;
                        bit_set(&mut bytes, bit, (digit >> j) & 0x1 != 0);
                        i += 1;
                    }
                }
            } else {
                return Err("Wrong data");
            }
        }

        if i % 8 != 0 {
            return Err("Not byte aligned");
        }

        Ok(Packet { bytes })
    }
}

struct PlaceholderParams {
    name: String,
    max_len: Option<usize>,
}

enum Placeholder {
    Hexadecimal(PlaceholderParams),
    Binary(PlaceholderParams),
    Raw(PlaceholderParams),
    String(PlaceholderParams),
    StaticText(String),
}

struct TokenList {
    tokens: Vec<Placeholder>
}

impl Placeholder {
    fn _parse_format(name: &str, format: &str) -> Result<Self, &'static str> {
        if format.ends_with("x") {
            let format = &format[0..format.len() - 1];
            let format = if format.len() == 0 {
                "0"
            } else {
                format
            };

            Ok(Self::Hexadecimal(PlaceholderParams {
                name: String::from(name),
                max_len: Some(format.parse().map_err(|_| "Unknown format code")?),
            }))
        } else if format.ends_with("s") {
            let format = &format[0..format.len() - 1];
            let format = if format.len() == 0 {
                "0"
            } else {
                format
            };

            Ok(Self::String(PlaceholderParams {
                name: String::from(name),
                max_len: Some(format.parse().map_err(|_| "Unknown format code")?),
            }))
        } else if format.ends_with("b") {
            let format = &format[0..format.len() - 1];
            let format = if format.len() == 0 {
                "0"
            } else {
                format
            };

            Ok(Self::Binary(PlaceholderParams {
                name: String::from(name),
                max_len: Some(format.parse().map_err(|_| "Unknown format code")?),
            }))
        } else if format.ends_with("r") {
            let format = &format[0..format.len() - 1];
            let format = if format.len() == 0 {
                "0"
            } else {
                format
            };

            Ok(Self::Raw(PlaceholderParams {
                name: String::from(name),
                max_len: Some(format.parse().map_err(|_| "Unknown format code")?),
            }))
        } else {
            Ok(Self::String(PlaceholderParams {
                name: String::from(name),
                max_len: Some(format.parse().map_err(|_| "Unknown format code")?),
            }))
        }
    }

    /// Create `Placeholder` from `expr` expression
    fn parse(expr: &str) -> Result<Self, &'static str> {
        if !expr.starts_with("{") || !expr.ends_with("}") {
            return Ok(Self::StaticText(String::from(expr)));
        }

        let expr = &expr[1..expr.len() - 1];
        let parts : Vec<_> = expr.split(":").collect();

        match parts.len() {
            1 => Ok(Self::String(PlaceholderParams {
                name: String::from(parts[0]),
                max_len: None,
            })),
            2 => Self::_parse_format(parts[0], parts[1]),
            _ => Err("Invalid format specified (too many \":\")"),
        }
    }

    /// Return default value for placeholder
    fn default_val(&self) -> &'static str {
        match self {
            Self::Hexadecimal(p) | Self::Binary(p) | Self::Raw(p) => "0",
            Self::String(p) => "",
            Self::StaticText(name) => "",
        }
    }

    fn pad_char(&self) -> char {
        match self {
            Self::Hexadecimal(p) | Self::Binary(p) | Self::Raw(p) => '0',
            Self::String(p) => ' ',
            Self::StaticText(name) => ' ',
        }
    }

    /// Check if placeholder is empty
    fn empty(&self) -> bool {
        if let Self::StaticText(s) = self {
            s.len() == 0
        } else {
            false
        }
    }

    fn parse_tokens(expr: &str) -> Result<Vec<Self>, &'static str> {
        let mut tokens = Vec::new();
        let mut start : usize = 0;

        for (i, c) in expr.chars().enumerate() {
            if i <= start {
                continue
            }

            if c == '{' {
                tokens.push(Placeholder::parse(&expr[start..i])?);
                start = i
            }
            if c == '}' {
                tokens.push(Placeholder::parse(&expr[start..i+1])?);
                start = i + 1;
            }
        }

        let last = Placeholder::parse(&expr[start..])?;

        if !last.empty() {
            tokens.push(Placeholder::parse(&expr[start..])?);
        }

        Ok(tokens)
    }

    fn to_hex(expr: &str) -> Result<String, &'static str>
    {
        if (expr.startswith("0x")) {
            String::from
        } else if expr.startswith("0b") {
            // from binary
        } else {
            // from decimal
        }
    }

    fn eval(&self, expr: Option<&str>) -> Result<String, &'static str> {

        let val = expr.unwrap_or(self.default_val());

        match self {
            Self::Hexadecimal(p) | Self::Binary(p) | Self::Raw(p) => {
                let value = format!("{}", val);

                Ok(strlpad(&value, p.max_len.unwrap_or(0), self.pad_char()))
            },
            Self::String(p) => {
                let value = format!("{}", val);

                Ok(strlpad(&value, p.max_len.unwrap_or(0), self.pad_char()))
            }
            Self::StaticText(name) => {
                Ok(format!("{}", name))
            },
        }
    }
}

impl fmt::Display for Placeholder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hexadecimal(p) | Self::Binary(p) | Self::Raw(p) | Self::String(p) => {
                if let Some(max_len) = p.max_len {
                    write!(f, "{{{}:{}}}", p.name, max_len)
                } else {
                    write!(f, "{{{}}}", p.name)
                }
            },
            Self::StaticText(name) => {
                write!(f, "{}", name)
            },
        }
    }
}

fn main() -> Result<(), Box<dyn Error>>{

    let bytes = env::args().skip(1).collect::<Vec<_>>().join(" ");

    let packet = Packet::from_byte_str(&bytes)?;

    let mut stdout = io::stdout().lock();

    stdout.write_all(&packet.bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_hex_str() {
        assert!(valid_hex_str("0xA"));
        assert!(valid_hex_str("0xABCDEF0123456789"));

        assert!(!valid_hex_str("foo"));
        assert!(!valid_hex_str(""));
        assert!(!valid_hex_str(" "));
        assert!(!valid_hex_str("a"));
        assert!(!valid_hex_str("A"));
        assert!(!valid_hex_str("ABCDEF0123456789"));
    }

    #[test]
    fn test_bit_set() {
        let mut v : Vec<u8> = Vec::new();

        bit_set(&mut v, 0, true);
        assert_eq!(0x1, v[0]);

        bit_set(&mut v, 1, true);
        assert_eq!(0x3, v[0]);
        assert_eq!(1, v.len());

        bit_set(&mut v, 8, true);
        assert_eq!(2, v.len());
        assert_eq!(0x3, v[0]);
        assert_eq!(0x1, v[1]);

        bit_set(&mut v, 8, false);
        assert_eq!(0x0, v[1]);

        bit_set(&mut v, 1, false);
        assert_eq!(0x1, v[0]);

        bit_set(&mut v, 0, false);
        assert_eq!(0x0, v[0]);
    }

    #[test]
    fn test_strlpad() {
        assert_eq!(strlpad("hello", 10, ' '), "     hello");
        assert_eq!(strlpad("hello", 1, ' '), "hello");
        assert_eq!(strlpad("hello", 7, '0'), "00hello");
        assert_eq!(strlpad("", 7, '0'), "0000000");
    }

    #[test]
    fn test_strrpad() {
        assert_eq!(strrpad("hello", 10, ' '), "hello     ");
        assert_eq!(strrpad("hello", 1, ' '), "hello");
        assert_eq!(strrpad("hello", 7, '0'), "hello00");
        assert_eq!(strrpad("", 7, '0'), "0000000");
    }

    #[test]
    fn test_packet_from_byte_str() {
        assert_eq!(Packet::from_byte_str("0b00000001").unwrap().bytes, vec![0b00000001]);
        assert_eq!(Packet::from_byte_str("0b0000 0x1").unwrap().bytes, vec![0b00000001]);
        assert_eq!(Packet::from_byte_str("0b00 0x1 0b01").unwrap().bytes, vec![0b00000101]);
        assert_eq!(Packet::from_byte_str("0b00  0x1  0b01").unwrap().bytes, vec![0b00000101]);
        assert_eq!(Packet::from_byte_str("0x01").unwrap().bytes, vec![0x01]);
        assert_eq!(Packet::from_byte_str("0x20").unwrap().bytes, vec![0x20]);
        assert_eq!(Packet::from_byte_str("0x1020").unwrap().bytes, vec![0x10, 0x20]);
        assert_eq!(Packet::from_byte_str("0x1020 0x3040").unwrap().bytes, vec![0x10, 0x20, 0x30, 0x40]);

        assert!(Packet::from_byte_str("0b0000001").is_err());
        assert!(Packet::from_byte_str("0b1").is_err());
        assert!(Packet::from_byte_str("0b").is_err());
        assert!(Packet::from_byte_str("0").is_err());
        assert!(Packet::from_byte_str("0x1").is_err());
        assert!(Packet::from_byte_str("0x123").is_err());
        assert!(Packet::from_byte_str("1020 0x3040").is_err());
        assert!(Packet::from_byte_str("0b00  0x1  0b").is_err());
        assert!(Packet::from_byte_str("0b10000000111100000b00001111").is_err())
    }

    fn to_s<T: std::fmt::Display>(x: Vec<T>) -> String {
        format!("#{} {}", x.len(), x.iter().map(|t| format!("{}", t)).collect::<Vec<_>>().join(""))
    }

    #[test]
    fn test_placeholder() {
        assert!(matches!(Placeholder::parse("{foo}").unwrap(), Placeholder::String(p) if p.name == "foo" && p.max_len.is_none()));
        assert!(matches!(Placeholder::parse("{bar}").unwrap(), Placeholder::String(p) if p.name == "bar" && p.max_len.is_none()));
        assert!(matches!(Placeholder::parse("{bar:4}").unwrap(), Placeholder::String(p) if p.name == "bar" && p.max_len.unwrap() == 4));

        assert!(matches!(Placeholder::parse("{bar:4").unwrap(), Placeholder::StaticText(p) if p == "{bar:4"));
        assert!(matches!(Placeholder::parse("").unwrap(), Placeholder::StaticText(p) if p == ""));
        assert!(matches!(Placeholder::parse("bar:4}").unwrap(), Placeholder::StaticText(p) if p == "bar:4}"));

        assert!(Placeholder::parse("{bar::4}").is_err());
        assert!(Placeholder::parse("{bar:a}").is_err());
        assert!(Placeholder::parse("{bar:}").is_err());
    }

    #[test]
    fn test_placeholder_tokens() {
        assert_eq!(to_s(Placeholder::parse_tokens("foo").unwrap()), "#1 foo");
        assert_eq!(to_s(Placeholder::parse_tokens("foo{bar}").unwrap()), "#2 foo{bar}");
        assert_eq!(to_s(Placeholder::parse_tokens("foo{bar:4}").unwrap()), "#2 foo{bar:4}");
        assert_eq!(to_s(Placeholder::parse_tokens("foo{bar:4}{foo}{foo}").unwrap()), "#4 foo{bar:4}{foo}{foo}");
    }

    #[test]
    fn test_placeholder_eval() {
        assert_eq!(Placeholder::parse("foo").unwrap().eval(None).unwrap(), "foo");
        assert_eq!(Placeholder::parse("{bar}").unwrap().eval(Some("baz")).unwrap(), "baz");
        assert_eq!(Placeholder::parse("{bar}").unwrap().eval(None).unwrap(), "");
        assert_eq!(Placeholder::parse("{bar:4}").unwrap().eval(None).unwrap(), "    ");
        assert_eq!(Placeholder::parse("{bar:4}").unwrap().eval(Some("x")).unwrap(), "   x");
        assert_eq!(Placeholder::parse("{bar:4s}").unwrap().eval(Some("x")).unwrap(), "   x");
        assert_eq!(Placeholder::parse("{bar:s}").unwrap().eval(Some("x")).unwrap(), "x");
    }
}
