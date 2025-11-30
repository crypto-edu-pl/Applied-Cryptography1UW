use std::collections::HashMap;

use urlencoding::{decode, encode};

pub fn encode_userdata(userdata: &str) -> String {
    let escaped = encode(userdata);
    format!("comment1=cooking%20MCs;userdata={escaped};comment2=%20like%20a%20pound%20of%20bacon")
}

fn split_2(input: &str, separator: char) -> Option<(&str, &str)> {
    let mut split = input.split(separator);

    let v1 = split.next()?;
    let v2 = split.next()?;
    if split.next().is_some() {
        return None;
    }
    Some((v1, v2))
}

pub fn parse_cookie(cookie: &str) -> Result<HashMap<String, String>, ParseCookieError> {
    let mut values = HashMap::new();
    for pair in cookie.split(';') {
        let (key, value) = split_2(pair, '=').ok_or(ParseCookieError::InvalidCookieFormat)?;
        let decoded_value = decode(value).map_err(|_| ParseCookieError::InvalidUrlEncoding)?;
        values.insert(key.to_string(), decoded_value.to_string());
    }
    Ok(values)
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseCookieError {
    #[error("Invalid cookie format")]
    InvalidCookieFormat,
    #[error("Invalid URL encoding")]
    InvalidUrlEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookie() {
        let cookie = encode_userdata("some_user_data");
        let values = parse_cookie(&cookie).unwrap();
        let expected = HashMap::from([
            ("comment1".to_string(), "cooking MCs".to_string()),
            ("comment2".to_string(), " like a pound of bacon".to_string()),
            ("userdata".to_string(), "some_user_data".to_string()),
        ]);
        assert_eq!(values, expected);
    }

    #[test]
    fn test_userdata_sanitization() {
        let cookie = encode_userdata("something;x=y");
        let values = parse_cookie(&cookie).unwrap();
        let expected = HashMap::from([
            ("comment1".to_string(), "cooking MCs".to_string()),
            ("comment2".to_string(), " like a pound of bacon".to_string()),
            ("userdata".to_string(), "something;x=y".to_string()),
        ]);
        assert_eq!(values, expected);
    }

    #[test]
    fn test_invalid_cookie_multiple_equals() {
        let cookie = "x=y=z".to_string();
        let values = parse_cookie(&cookie);
        assert_eq!(values, Err(ParseCookieError::InvalidCookieFormat));
    }

    #[test]
    fn test_invalid_cookie_no_equals() {
        let cookie = "x".to_string();
        let values = parse_cookie(&cookie);
        assert_eq!(values, Err(ParseCookieError::InvalidCookieFormat));
    }

    #[test]
    fn test_invalid_cookie_non_utf8() {
        let cookie = "x=%FF".to_string();
        let values = parse_cookie(&cookie);
        assert_eq!(values, Err(ParseCookieError::InvalidUrlEncoding));
    }
}
