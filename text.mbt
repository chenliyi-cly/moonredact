///|
fn is_ascii_lower(value : Char) -> Bool {
  value >= 'a' && value <= 'z'
}

///|
fn is_ascii_upper(value : Char) -> Bool {
  value >= 'A' && value <= 'Z'
}

///|
fn is_ascii_letter(value : Char) -> Bool {
  is_ascii_lower(value) || is_ascii_upper(value)
}

///|
fn is_ascii_digit(value : Char) -> Bool {
  value >= '0' && value <= '9'
}

///|
fn is_ascii_alphanumeric(value : Char) -> Bool {
  is_ascii_letter(value) || is_ascii_digit(value)
}

///|
fn is_ascii_word(value : Char) -> Bool {
  is_ascii_alphanumeric(value) || value == '_'
}

///|
fn is_horizontal_space(value : Char) -> Bool {
  value == ' ' || value == '\t'
}

///|
fn ascii_lower(value : Char) -> Char {
  if is_ascii_upper(value) {
    (value.to_int() + ('a'.to_int() - 'A'.to_int())).to_char().unwrap()
  } else {
    value
  }
}

///|
fn ascii_lower_text(value : String) -> String {
  let output = StringBuilder::new()
  for char in value {
    output.write_char(ascii_lower(char))
  }
  output.to_string()
}

///|
fn text_slice(source : String, start : Int, end : Int) -> String {
  source[start:end].to_owned()
}

///|
fn parse_ascii_uint(source : String) -> Result[Int, Diagnostic] {
  if source.is_empty() {
    return Err(
      Diagnostic::new(
        "number.empty", "number", "number is empty", "ASCII digits", "empty",
      ),
    )
  }
  let mut result = 0
  for char in source {
    if !is_ascii_digit(char) {
      return Err(
        Diagnostic::new(
          "number.character.invalid",
          "number",
          "number contains a non-digit",
          "ASCII digits",
          char.to_string(),
        ),
      )
    }
    result = result * 10 + char.to_int() - '0'.to_int()
  }
  Ok(result)
}

///|
fn contains_exact(values : Array[String], candidate : String) -> Bool {
  for value in values {
    if value == candidate {
      return true
    }
  }
  false
}

///|
fn starts_with_at(
  source : Array[Char],
  offset : Int,
  needle : Array[Char],
  case_sensitive : Bool,
) -> Bool {
  if needle.is_empty() ||
    offset < 0 ||
    offset + needle.length() > source.length() {
    return false
  }
  for index = 0; index < needle.length(); index = index + 1 {
    let left = source[offset + index]
    let right = needle[index]
    if case_sensitive {
      if left != right {
        return false
      }
    } else if ascii_lower(left) != ascii_lower(right) {
      return false
    }
  }
  true
}

///|
fn has_word_boundaries(source : Array[Char], start : Int, end : Int) -> Bool {
  let left_ok = start == 0 || !is_ascii_word(source[start - 1])
  let right_ok = end == source.length() || !is_ascii_word(source[end])
  left_ok && right_ok
}

///|
fn stable_text_hash(source : String, salt : String) -> String {
  let mut value = 146959810
  for char in salt + "|" + source {
    value = (value * 16777619 + char.to_int()) % 2147483629
    if value < 0 {
      value = value + 2147483629
    }
  }
  let alphabet = "0123456789abcdefghijklmnopqrstuvwxyz".to_array()
  let output = StringBuilder::new()
  let mut remaining = value
  for index = 0; index < 8; index = index + 1 {
    output.write_char(alphabet[remaining % 36])
    remaining = remaining / 36
  }
  output.to_string()
}
