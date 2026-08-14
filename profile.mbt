///|
/// Complete validated runtime configuration parsed from a profile.
pub struct RedactionProfile {
  scan_config : ScanConfig
  policy : RedactionPolicy
} derive(Eq, @debug.Debug)

///|
pub fn RedactionProfile::new(
  scan_config : ScanConfig,
  policy : RedactionPolicy,
) -> RedactionProfile {
  { scan_config, policy }
}

///|
pub fn RedactionProfile::balanced() -> RedactionProfile {
  { scan_config: ScanConfig::default(), policy: RedactionPolicy::balanced() }
}

///|
pub fn RedactionProfile::scan_config(self : RedactionProfile) -> ScanConfig {
  self.scan_config
}

///|
pub fn RedactionProfile::policy(self : RedactionProfile) -> RedactionPolicy {
  self.policy
}

///|
fn profile_location(line : Int, field : String) -> String {
  "profile.line[" + line.to_string() + "]." + field
}

///|
fn split_owned(source : String, separator : String) -> Array[String] {
  source.split(separator).map(fn(value) { value.to_owned() }).collect()
}

///|
fn parse_profile_int(
  source : String,
  location : String,
) -> Result[Int, Diagnostic] {
  match parse_ascii_uint(source.trim().to_owned()) {
    Ok(value) => Ok(value)
    Err(_) =>
      Err(
        Diagnostic::new(
          "profile.integer.invalid", location, "integer value is invalid", "non-negative ASCII integer",
          source,
        ),
      )
  }
}

///|
/// Parse a redaction action: keep, remove, mask:N, or token:PREFIX.
pub fn parse_action(
  source : String,
  location? : String = "action",
) -> Result[RedactionAction, Diagnostic] {
  let normalized = source.trim().to_owned()
  if ascii_lower_text(normalized) == "keep" {
    return Ok(Keep)
  }
  if ascii_lower_text(normalized) == "remove" {
    return Ok(Remove)
  }
  if ascii_lower_text(normalized).has_prefix("mask:") {
    let visible = match parse_profile_int(normalized[5:].to_owned(), location) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let action = Mask(visible)
    return match validate_action(action, location) {
      Ok(_) => Ok(action)
      Err(error) => Err(error)
    }
  }
  if ascii_lower_text(normalized).has_prefix("token:") {
    let action = Token(normalized[6:].to_owned())
    return match validate_action(action, location) {
      Ok(_) => Ok(action)
      Err(error) => Err(error)
    }
  }
  Err(
    Diagnostic::new(
      "profile.action.invalid", location, "redaction action is unsupported", "keep, remove, mask:N, or token:PREFIX",
      normalized,
    ),
  )
}

///|
fn parse_detector_list(
  source : String,
  config : ScanConfig,
  location : String,
) -> Result[ScanConfig, Diagnostic] {
  let mut result = config
    .with_email(false)
    .with_ipv4(false)
    .with_payment_card(false)
    .with_credential(false)
  if ascii_lower_text(source.trim().to_owned()) == "none" {
    return Ok(result)
  }
  let mut seen = 0
  for raw in split_owned(source, ",") {
    let value = ascii_lower_text(raw.trim().to_owned())
    match value {
      "email" => {
        result = result.with_email(true)
        seen = seen + 1
      }
      "ipv4" => {
        result = result.with_ipv4(true)
        seen = seen + 1
      }
      "payment-card" | "card" => {
        result = result.with_payment_card(true)
        seen = seen + 1
      }
      "credential" | "secret" => {
        result = result.with_credential(true)
        seen = seen + 1
      }
      _ =>
        return Err(
          Diagnostic::new(
            "profile.detector.unknown", location, "detector name is unsupported",
            "email, ipv4, payment-card, or credential", value,
          ),
        )
    }
  }
  if seen == 0 {
    Err(
      Diagnostic::new(
        "profile.detectors.empty", location, "detector list is empty", "at least one detector",
        "empty",
      ),
    )
  } else {
    Ok(result)
  }
}

///|
fn parse_dictionary_flags(
  source : String,
  location : String,
) -> Result[(Bool, Bool), Diagnostic] {
  let normalized = ascii_lower_text(source.trim().to_owned())
  match normalized {
    "exact" => Ok((true, false))
    "fold" => Ok((false, false))
    "word" | "exact-word" => Ok((true, true))
    "fold-word" => Ok((false, true))
    _ =>
      Err(
        Diagnostic::new(
          "profile.dictionary.flags", location, "dictionary matching mode is unsupported",
          "exact, fold, word, or fold-word", normalized,
        ),
      )
  }
}

///|
fn parse_dictionary_term(
  source : String,
  location : String,
) -> Result[DictionaryTerm, Diagnostic] {
  let fields = split_owned(source, "|")
  if fields.length() != 4 {
    return Err(
      Diagnostic::new(
        "profile.dictionary.fields",
        location,
        "dictionary entry has the wrong field count",
        "name|value|mode|priority",
        fields.length().to_string() + " fields",
      ),
    )
  }
  let flags = match parse_dictionary_flags(fields[2], location + ".mode") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let priority = match parse_profile_int(fields[3], location + ".priority") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  DictionaryTerm::new(
    fields[0],
    fields[1],
    case_sensitive=flags.0,
    whole_word=flags.1,
    priority~,
  )
}

///|
fn parse_policy_rule(
  source : String,
  location : String,
) -> Result[PolicyRule, Diagnostic] {
  let fields = split_owned(source, "|")
  if fields.length() != 3 {
    return Err(
      Diagnostic::new(
        "profile.rule.fields",
        location,
        "policy rule has the wrong field count",
        "selector|action|priority",
        fields.length().to_string() + " fields",
      ),
    )
  }
  let action = match parse_action(fields[1], location=location + ".action") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let priority = match parse_profile_int(fields[2], location + ".priority") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  PolicyRule::new(fields[0], action, priority~)
}

///|
/// Parse the bounded line-oriented MoonRedact profile format.
pub fn parse_profile(source : String) -> Result[RedactionProfile, Diagnostic] {
  if source.length() > 262144 {
    return Err(
      Diagnostic::new(
        "profile.input.limit",
        "profile",
        "profile exceeds the safety limit",
        "at most 262144 characters",
        source.length().to_string(),
      ),
    )
  }
  let lines : Array[String] = source
    .split("\n")
    .map(fn(value) { value.to_owned() })
    .collect()
  let mut config = ScanConfig::default()
  let allowlist : Array[String] = []
  let dictionary : Array[DictionaryTerm] = []
  let credential_keys : Array[String] = []
  let rules : Array[PolicyRule] = []
  let mut default_action : RedactionAction = Mask(0)
  let mut salt = "moonredact-v1"
  let mut saw_default = false
  let mut saw_salt = false
  let mut saw_detectors = false
  let mut saw_limit = false
  for index, raw_line in lines {
    let line = raw_line.trim().to_owned()
    if line.is_empty() || line.has_prefix("#") {
      continue
    }
    let separator = match line.find("=") {
      Some(value) => value
      None =>
        return Err(
          Diagnostic::new(
            "profile.assignment.missing",
            profile_location(index + 1, "line"),
            "profile line has no assignment separator",
            "key=value",
            line,
          ),
        )
    }
    let key = ascii_lower_text(line[:separator].trim().to_owned())
    let value = line[separator + 1:].trim().to_owned()
    let location = profile_location(index + 1, key)
    match key {
      "detectors" => {
        if saw_detectors {
          return Err(
            Diagnostic::new(
              "profile.detectors.duplicate", location, "detectors is assigned more than once",
              "one assignment", "duplicate",
            ),
          )
        }
        config = match parse_detector_list(value, config, location) {
          Ok(result) => result
          Err(error) => return Err(error)
        }
        saw_detectors = true
      }
      "max-input" => {
        if saw_limit {
          return Err(
            Diagnostic::new(
              "profile.max-input.duplicate", location, "max-input is assigned more than once",
              "one assignment", "duplicate",
            ),
          )
        }
        let limit = match parse_profile_int(value, location) {
          Ok(result) => result
          Err(error) => return Err(error)
        }
        config = match config.with_max_input_chars(limit) {
          Ok(result) => result
          Err(error) => return Err(error)
        }
        saw_limit = true
      }
      "allow" => {
        if value.is_empty() {
          return Err(
            Diagnostic::new(
              "profile.allow.empty", location, "allowlist value is empty", "non-empty value",
              "empty",
            ),
          )
        }
        allowlist.push(value)
      }
      "dictionary" => {
        let term = match parse_dictionary_term(value, location) {
          Ok(result) => result
          Err(error) => return Err(error)
        }
        dictionary.push(term)
      }
      "credential-key" => credential_keys.push(value)
      "default" => {
        if saw_default {
          return Err(
            Diagnostic::new(
              "profile.default.duplicate", location, "default action is assigned more than once",
              "one assignment", "duplicate",
            ),
          )
        }
        default_action = match parse_action(value, location~) {
          Ok(result) => result
          Err(error) => return Err(error)
        }
        saw_default = true
      }
      "salt" => {
        if saw_salt {
          return Err(
            Diagnostic::new(
              "profile.salt.duplicate", location, "salt is assigned more than once",
              "one assignment", "duplicate",
            ),
          )
        }
        salt = value
        saw_salt = true
      }
      "rule" => {
        let rule = match parse_policy_rule(value, location) {
          Ok(result) => result
          Err(error) => return Err(error)
        }
        rules.push(rule)
      }
      _ =>
        return Err(
          Diagnostic::new(
            "profile.key.unknown", location, "profile key is unsupported", "documented profile key",
            key,
          ),
        )
    }
  }
  config = match config.with_allowlist(allowlist) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  config = match config.with_dictionary(dictionary) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if !credential_keys.is_empty() {
    config = match config.with_credential_keys(credential_keys) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
  }
  let policy = match
    RedactionPolicy::new(default_action~, rules~, token_salt=salt) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ scan_config: config, policy })
}

///|
pub fn RedactionProfile::canonical(self : RedactionProfile) -> String {
  let output = StringBuilder::new()
  let detectors : Array[String] = []
  if self.scan_config.detect_email {
    detectors.push("email")
  }
  if self.scan_config.detect_ipv4 {
    detectors.push("ipv4")
  }
  if self.scan_config.detect_payment_card {
    detectors.push("payment-card")
  }
  if self.scan_config.detect_credential {
    detectors.push("credential")
  }
  output.write_string("detectors=")
  if detectors.is_empty() {
    output.write_string("none")
  } else {
    for index, detector in detectors {
      if index > 0 {
        output.write_char(',')
      }
      output.write_string(detector)
    }
  }
  output.write_string(
    "\nmax-input=" + self.scan_config.max_input_chars.to_string() + "\n",
  )
  for value in self.scan_config.allowlist {
    output.write_string("allow=" + value + "\n")
  }
  for term in self.scan_config.dictionary {
    let mode = if term.case_sensitive {
      if term.whole_word {
        "word"
      } else {
        "exact"
      }
    } else if term.whole_word {
      "fold-word"
    } else {
      "fold"
    }
    output.write_string(
      "dictionary=" +
      term.name +
      "|" +
      term.value +
      "|" +
      mode +
      "|" +
      term.priority.to_string() +
      "\n",
    )
  }
  for key in self.scan_config.credential_keys {
    output.write_string("credential-key=" + key + "\n")
  }
  output.write_string("default=" + self.policy.default_action.label() + "\n")
  output.write_string("salt=" + self.policy.token_salt + "\n")
  for rule in self.policy.rules {
    output.write_string(
      "rule=" +
      rule.selector +
      "|" +
      rule.action.label() +
      "|" +
      rule.priority.to_string() +
      "\n",
    )
  }
  output.to_string()
}
