///|
/// Detector configuration. All built-in detectors are enabled by default.
pub struct ScanConfig {
  detect_email : Bool
  detect_ipv4 : Bool
  detect_payment_card : Bool
  detect_credential : Bool
  max_input_chars : Int
  allowlist : Array[String]
  dictionary : Array[DictionaryTerm]
  credential_keys : Array[String]
} derive(Eq, @debug.Debug)

///|
pub fn ScanConfig::default() -> ScanConfig {
  {
    detect_email: true,
    detect_ipv4: true,
    detect_payment_card: true,
    detect_credential: true,
    max_input_chars: 1_000_000,
    allowlist: [],
    dictionary: [],
    credential_keys: [
      "password", "passwd", "token", "secret", "api_key", "apikey", "authorization",
    ],
  }
}

///|
pub fn ScanConfig::with_email(self : ScanConfig, enabled : Bool) -> ScanConfig {
  { ..self, detect_email: enabled }
}

///|
pub fn ScanConfig::with_ipv4(self : ScanConfig, enabled : Bool) -> ScanConfig {
  { ..self, detect_ipv4: enabled }
}

///|
pub fn ScanConfig::with_payment_card(
  self : ScanConfig,
  enabled : Bool,
) -> ScanConfig {
  { ..self, detect_payment_card: enabled }
}

///|
pub fn ScanConfig::with_credential(
  self : ScanConfig,
  enabled : Bool,
) -> ScanConfig {
  { ..self, detect_credential: enabled }
}

///|
pub fn ScanConfig::with_max_input_chars(
  self : ScanConfig,
  limit : Int,
) -> Result[ScanConfig, Diagnostic] {
  if limit < 1 || limit > 10_000_000 {
    Err(
      Diagnostic::new(
        "config.input-limit.invalid",
        "config.max-input-chars",
        "input limit is outside the supported range",
        "1 through 10000000",
        limit.to_string(),
      ),
    )
  } else {
    Ok({ ..self, max_input_chars: limit })
  }
}

///|
pub fn ScanConfig::with_allowlist(
  self : ScanConfig,
  values : Array[String],
) -> Result[ScanConfig, Diagnostic] {
  if values.length() > 10000 {
    return Err(
      Diagnostic::new(
        "config.allowlist.limit",
        "config.allowlist",
        "allowlist has too many entries",
        "at most 10000 entries",
        values.length().to_string(),
      ),
    )
  }
  let normalized : Array[String] = []
  for value in values {
    if value.is_empty() {
      return Err(
        Diagnostic::new(
          "config.allowlist.empty", "config.allowlist", "allowlist contains an empty value",
          "non-empty values", "empty",
        ),
      )
    }
    if !contains_exact(normalized, value) {
      normalized.push(value)
    }
  }
  Ok({ ..self, allowlist: normalized })
}

///|
pub fn ScanConfig::with_dictionary(
  self : ScanConfig,
  terms : Array[DictionaryTerm],
) -> Result[ScanConfig, Diagnostic] {
  if terms.length() > 1000 {
    Err(
      Diagnostic::new(
        "config.dictionary.limit",
        "config.dictionary",
        "dictionary has too many entries",
        "at most 1000 entries",
        terms.length().to_string(),
      ),
    )
  } else {
    Ok({ ..self, dictionary: terms.copy() })
  }
}

///|
pub fn ScanConfig::with_credential_keys(
  self : ScanConfig,
  keys : Array[String],
) -> Result[ScanConfig, Diagnostic] {
  if keys.is_empty() {
    return Err(
      Diagnostic::new(
        "config.credential-keys.empty", "config.credential-keys", "credential key list is empty",
        "at least one key", "empty",
      ),
    )
  }
  let normalized : Array[String] = []
  for key in keys {
    let value = ascii_lower_text(key.trim().to_owned())
    if value.is_empty() {
      return Err(
        Diagnostic::new(
          "config.credential-key.empty", "config.credential-keys", "credential key is empty",
          "non-empty key", "empty",
        ),
      )
    }
    for char in value {
      if !is_ascii_word(char) && char != '-' {
        return Err(
          Diagnostic::new(
            "config.credential-key.invalid",
            "config.credential-keys",
            "credential key contains an unsupported character",
            "ASCII letter, digit, underscore, or hyphen",
            char.to_string(),
          ),
        )
      }
    }
    if !contains_exact(normalized, value) {
      normalized.push(value)
    }
  }
  Ok({ ..self, credential_keys: normalized })
}

///|
pub fn ScanConfig::allowlist(self : ScanConfig) -> Array[String] {
  self.allowlist.copy()
}

///|
pub fn ScanConfig::dictionary(self : ScanConfig) -> Array[DictionaryTerm] {
  self.dictionary.copy()
}

///|
pub fn ScanConfig::max_input_chars(self : ScanConfig) -> Int {
  self.max_input_chars
}
