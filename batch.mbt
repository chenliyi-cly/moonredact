///|
pub struct NamedInput {
  name : String
  content : String
} derive(Eq, @debug.Debug)

///|
pub fn NamedInput::new(
  name : String,
  content : String,
) -> Result[NamedInput, Diagnostic] {
  if name.trim().is_empty() {
    Err(
      Diagnostic::new(
        "batch.name.empty", "batch.name", "input name is empty", "non-empty name",
        "empty",
      ),
    )
  } else if name.length() > 256 {
    Err(
      Diagnostic::new(
        "batch.name.limit",
        "batch.name",
        "input name exceeds the safety limit",
        "at most 256 characters",
        name.length().to_string(),
      ),
    )
  } else {
    Ok({ name: name.trim().to_owned(), content })
  }
}

///|
pub fn NamedInput::name(self : NamedInput) -> String {
  self.name
}

///|
pub fn NamedInput::content(self : NamedInput) -> String {
  self.content
}

///|
pub struct NamedResult {
  name : String
  result : RedactionResult
  audit : AuditReport
} derive(Eq, @debug.Debug)

///|
pub fn NamedResult::name(self : NamedResult) -> String {
  self.name
}

///|
pub fn NamedResult::result(self : NamedResult) -> RedactionResult {
  self.result
}

///|
pub fn NamedResult::audit(self : NamedResult) -> AuditReport {
  self.audit
}

///|
pub struct BatchResult {
  items : Array[NamedResult]
  total_inputs : Int
  total_characters : Int
  total_findings : Int
  total_changed : Int
} derive(Eq, @debug.Debug)

///|
pub fn redact_batch(
  inputs : Array[NamedInput],
  profile? : RedactionProfile = RedactionProfile::balanced(),
) -> Result[BatchResult, Diagnostic] {
  if inputs.length() > 10000 {
    return Err(
      Diagnostic::new(
        "batch.input-count.limit",
        "batch",
        "batch has too many inputs",
        "at most 10000 inputs",
        inputs.length().to_string(),
      ),
    )
  }
  let seen : Array[String] = []
  let items : Array[NamedResult] = []
  let mut characters = 0
  let mut findings = 0
  let mut changed = 0
  for input in inputs {
    if contains_exact(seen, input.name) {
      return Err(
        Diagnostic::new(
          "batch.name.duplicate",
          "batch." + input.name,
          "batch input name is duplicated",
          "unique name",
          input.name,
        ),
      )
    }
    seen.push(input.name)
    let result = match
      redact(input.content, config=profile.scan_config, policy=profile.policy) {
      Ok(value) => value
      Err(error) =>
        return Err(
          Diagnostic::new(
            error.code(),
            "batch." + input.name + "." + error.location(),
            error.message(),
            error.expected(),
            error.actual(),
          ),
        )
    }
    let summary = audit(result)
    characters = characters + summary.input_length()
    findings = findings + summary.accepted_count()
    changed = changed + summary.changed_count()
    items.push({ name: input.name, result, audit: summary })
  }
  Ok({
    items,
    total_inputs: inputs.length(),
    total_characters: characters,
    total_findings: findings,
    total_changed: changed,
  })
}

///|
pub fn BatchResult::items(self : BatchResult) -> Array[NamedResult] {
  self.items.copy()
}

///|
pub fn BatchResult::input_count(self : BatchResult) -> Int {
  self.total_inputs
}

///|
pub fn BatchResult::character_count(self : BatchResult) -> Int {
  self.total_characters
}

///|
pub fn BatchResult::finding_count(self : BatchResult) -> Int {
  self.total_findings
}

///|
pub fn BatchResult::changed_count(self : BatchResult) -> Int {
  self.total_changed
}

///|
pub struct ResidualReport {
  clean : Bool
  findings : Array[Finding]
} derive(Eq, @debug.Debug)

///|
/// Rescan sanitized output with the same detector configuration.
pub fn verify_sanitized(
  result : RedactionResult,
  config? : ScanConfig = ScanConfig::default(),
) -> Result[ResidualReport, Diagnostic] {
  let rescanned = match scan(result.sanitized_text(), config~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok({ clean: rescanned.findings.is_empty(), findings: rescanned.findings })
}

///|
pub fn ResidualReport::is_clean(self : ResidualReport) -> Bool {
  self.clean
}

///|
pub fn ResidualReport::findings(self : ResidualReport) -> Array[Finding] {
  self.findings.copy()
}
