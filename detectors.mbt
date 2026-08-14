///|
fn is_email_local_char(value : Char) -> Bool {
  is_ascii_alphanumeric(value) ||
  value == '.' ||
  value == '_' ||
  value == '%' ||
  value == '+' ||
  value == '-'
}

///|
fn is_email_domain_char(value : Char) -> Bool {
  is_ascii_alphanumeric(value) || value == '.' || value == '-'
}

///|
fn valid_email_candidate(value : String) -> Bool {
  let chars = value.to_array()
  let mut at = -1
  for index = 0; index < chars.length(); index = index + 1 {
    if chars[index] == '@' {
      if at >= 0 {
        return false
      }
      at = index
    }
  }
  if at <= 0 ||
    at >= chars.length() - 3 ||
    chars[0] == '.' ||
    chars[at - 1] == '.' {
    return false
  }
  let mut previous_dot = false
  for index = 0; index < at; index = index + 1 {
    if !is_email_local_char(chars[index]) ||
      (chars[index] == '.' && previous_dot) {
      return false
    }
    previous_dot = chars[index] == '.'
  }
  let mut has_dot = false
  let mut label_length = 0
  for index = at + 1; index < chars.length(); index = index + 1 {
    let current = chars[index]
    if !is_email_domain_char(current) {
      return false
    }
    if current == '.' {
      if label_length == 0 || chars[index - 1] == '-' {
        return false
      }
      has_dot = true
      label_length = 0
    } else {
      if label_length == 0 && current == '-' {
        return false
      }
      label_length = label_length + 1
    }
  }
  has_dot && label_length >= 2 && chars[chars.length() - 1] != '-'
}

///|
fn detect_emails(source : String) -> Array[Finding] {
  let chars = source.to_array()
  let findings : Array[Finding] = []
  for at = 0; at < chars.length(); at = at + 1 {
    if chars[at] == '@' {
      let mut start = at
      while start > 0 && is_email_local_char(chars[start - 1]) {
        start = start - 1
      }
      let mut end = at + 1
      while end < chars.length() && is_email_domain_char(chars[end]) {
        end = end + 1
      }
      let candidate = text_slice(source, start, end)
      if valid_email_candidate(candidate) {
        findings.push(
          make_finding(source, start, end, Email, "builtin.email", High, 80),
        )
      }
    }
  }
  findings
}

///|
fn valid_ipv4_candidate(value : String) -> Bool {
  let parts : Array[String] = value
    .split(".")
    .map(fn(part) { part.to_owned() })
    .collect()
  if parts.length() != 4 {
    return false
  }
  for part in parts {
    if part.is_empty() ||
      part.length() > 3 ||
      (part.length() > 1 && part[0] == '0') {
      return false
    }
    match parse_ascii_uint(part) {
      Ok(number) => if number > 255 { return false }
      Err(_) => return false
    }
  }
  true
}

///|
fn detect_ipv4_addresses(source : String) -> Array[Finding] {
  let chars = source.to_array()
  let findings : Array[Finding] = []
  let mut index = 0
  while index < chars.length() {
    if is_ascii_digit(chars[index]) &&
      (
        index == 0 ||
        (!is_ascii_digit(chars[index - 1]) && chars[index - 1] != '.')
      ) {
      let start = index
      let mut dots = 0
      while index < chars.length() &&
            (is_ascii_digit(chars[index]) || chars[index] == '.') {
        if chars[index] == '.' {
          dots = dots + 1
        }
        index = index + 1
      }
      if dots == 3 {
        let candidate = text_slice(source, start, index)
        if valid_ipv4_candidate(candidate) {
          findings.push(
            make_finding(source, start, index, IPv4, "builtin.ipv4", High, 70),
          )
        }
      }
    } else {
      index = index + 1
    }
  }
  findings
}

///|
fn luhn_valid(digits : Array[Int]) -> Bool {
  if digits.length() < 13 || digits.length() > 19 {
    return false
  }
  let mut sum = 0
  let mut double_digit = false
  let mut index = digits.length() - 1
  while index >= 0 {
    let mut value = digits[index]
    if double_digit {
      value = value * 2
      if value > 9 {
        value = value - 9
      }
    }
    sum = sum + value
    double_digit = !double_digit
    index = index - 1
  }
  sum % 10 == 0
}

///|
fn detect_payment_cards(source : String) -> Array[Finding] {
  let chars = source.to_array()
  let findings : Array[Finding] = []
  let mut index = 0
  while index < chars.length() {
    if is_ascii_digit(chars[index]) &&
      (
        index == 0 ||
        (!is_ascii_digit(chars[index - 1]) && chars[index - 1] != '-')
      ) {
      let start = index
      let digits : Array[Int] = []
      let mut cursor = index
      let mut end = index
      while cursor < chars.length() &&
            (
              is_ascii_digit(chars[cursor]) ||
              chars[cursor] == ' ' ||
              chars[cursor] == '-'
            ) {
        if is_ascii_digit(chars[cursor]) {
          digits.push(chars[cursor].to_int() - '0'.to_int())
          end = cursor + 1
        }
        cursor = cursor + 1
      }
      if luhn_valid(digits) &&
        (end == chars.length() || !is_ascii_digit(chars[end])) {
        findings.push(
          make_finding(
            source,
            start,
            end,
            PaymentCard,
            "builtin.payment-card.luhn",
            High,
            90,
          ),
        )
      }
      index = if cursor > index { cursor } else { index + 1 }
    } else {
      index = index + 1
    }
  }
  findings
}

///|
fn credential_value_end(chars : Array[Char], start : Int, quote : Char?) -> Int {
  let mut end = start
  while end < chars.length() {
    match quote {
      Some(delimiter) => if chars[end] == delimiter { return end }
      None =>
        if chars[end] == ' ' ||
          chars[end] == '\t' ||
          chars[end] == '\r' ||
          chars[end] == '\n' ||
          chars[end] == ',' ||
          chars[end] == ';' {
          return end
        }
    }
    end = end + 1
  }
  end
}

///|
fn detect_credentials(source : String, keys : Array[String]) -> Array[Finding] {
  let chars = source.to_array()
  let findings : Array[Finding] = []
  for key in keys {
    let key_chars = key.to_array()
    for start = 0
        start + key_chars.length() < chars.length()
        start = start + 1 {
      if starts_with_at(chars, start, key_chars, false) &&
        has_word_boundaries(chars, start, start + key_chars.length()) {
        let mut cursor = start + key_chars.length()
        while cursor < chars.length() && is_horizontal_space(chars[cursor]) {
          cursor = cursor + 1
        }
        if cursor < chars.length() &&
          (chars[cursor] == '=' || chars[cursor] == ':') {
          cursor = cursor + 1
          while cursor < chars.length() && is_horizontal_space(chars[cursor]) {
            cursor = cursor + 1
          }
          let quote = if cursor < chars.length() &&
            (chars[cursor] == '\'' || chars[cursor] == '"') {
            let result = Some(chars[cursor])
            cursor = cursor + 1
            result
          } else {
            None
          }
          let end = credential_value_end(chars, cursor, quote)
          if end > cursor {
            findings.push(
              make_finding(
                source,
                cursor,
                end,
                Credential,
                "builtin.credential:" + key,
                High,
                100,
              ),
            )
          }
        }
      }
    }
  }
  findings
}

///|
fn detect_dictionary(
  source : String,
  terms : Array[DictionaryTerm],
) -> Array[Finding] {
  let chars = source.to_array()
  let findings : Array[Finding] = []
  for term in terms {
    let needle = term.value.to_array()
    if needle.length() <= chars.length() {
      for start = 0
          start + needle.length() <= chars.length()
          start = start + 1 {
        let end = start + needle.length()
        if starts_with_at(chars, start, needle, term.case_sensitive) &&
          (!term.whole_word || has_word_boundaries(chars, start, end)) {
          findings.push(
            make_finding(
              source,
              start,
              end,
              Custom(term.name),
              "dictionary:" + term.name,
              if term.whole_word {
                Medium
              } else {
                Low
              },
              term.priority,
            ),
          )
        }
      }
    }
  }
  findings
}

///|
fn collect_candidates(source : String, config : ScanConfig) -> Array[Finding] {
  let findings : Array[Finding] = []
  if config.detect_email {
    for finding in detect_emails(source) {
      findings.push(finding)
    }
  }
  if config.detect_ipv4 {
    for finding in detect_ipv4_addresses(source) {
      findings.push(finding)
    }
  }
  if config.detect_payment_card {
    for finding in detect_payment_cards(source) {
      findings.push(finding)
    }
  }
  if config.detect_credential {
    for finding in detect_credentials(source, config.credential_keys) {
      findings.push(finding)
    }
  }
  for finding in detect_dictionary(source, config.dictionary) {
    findings.push(finding)
  }
  findings
}
