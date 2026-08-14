///|
pub struct PolicyChange {
  span : Span
  sensitivity : Sensitivity
  before : RedactionAction
  after : RedactionAction
  replacement_changed : Bool
} derive(Eq, @debug.Debug)

///|
pub fn PolicyChange::span(self : PolicyChange) -> Span {
  self.span
}

///|
pub fn PolicyChange::sensitivity(self : PolicyChange) -> Sensitivity {
  self.sensitivity
}

///|
pub fn PolicyChange::before(self : PolicyChange) -> RedactionAction {
  self.before
}

///|
pub fn PolicyChange::after(self : PolicyChange) -> RedactionAction {
  self.after
}

///|
pub fn PolicyChange::replacement_changed(self : PolicyChange) -> Bool {
  self.replacement_changed
}

///|
pub struct PolicyComparison {
  finding_count : Int
  changed : Array[PolicyChange]
  before_output_length : Int
  after_output_length : Int
} derive(Eq, @debug.Debug)

///|
/// Compare two policies over one scan without exposing matched source values.
pub fn compare_policies(
  source : String,
  before : RedactionPolicy,
  after : RedactionPolicy,
  config? : ScanConfig = ScanConfig::default(),
) -> Result[PolicyComparison, Diagnostic] {
  let scanned = match scan(source, config~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let before_result = match redact(source, config~, policy=before) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let after_result = match redact(source, config~, policy=after) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let changes : Array[PolicyChange] = []
  for finding in scanned.findings {
    let before_action = before.action_for(finding.sensitivity)
    let after_action = after.action_for(finding.sensitivity)
    let before_replacement = replacement_for(
      finding,
      before_action,
      before.token_salt,
    )
    let after_replacement = replacement_for(
      finding,
      after_action,
      after.token_salt,
    )
    if before_action != after_action || before_replacement != after_replacement {
      changes.push({
        span: finding.span,
        sensitivity: finding.sensitivity,
        before: before_action,
        after: after_action,
        replacement_changed: before_replacement != after_replacement,
      })
    }
  }
  Ok({
    finding_count: scanned.findings.length(),
    changed: changes,
    before_output_length: before_result.sanitized.length(),
    after_output_length: after_result.sanitized.length(),
  })
}

///|
pub fn PolicyComparison::finding_count(self : PolicyComparison) -> Int {
  self.finding_count
}

///|
pub fn PolicyComparison::changed_count(self : PolicyComparison) -> Int {
  self.changed.length()
}

///|
pub fn PolicyComparison::changes(
  self : PolicyComparison,
) -> Array[PolicyChange] {
  self.changed.copy()
}

///|
pub fn PolicyComparison::before_output_length(self : PolicyComparison) -> Int {
  self.before_output_length
}

///|
pub fn PolicyComparison::after_output_length(self : PolicyComparison) -> Int {
  self.after_output_length
}

///|
pub fn PolicyComparison::render_text(self : PolicyComparison) -> String {
  let output = StringBuilder::new()
  output.write_string("MoonRedact policy comparison\n")
  output.write_string("findings: " + self.finding_count.to_string() + "\n")
  output.write_string("changed: " + self.changed.length().to_string() + "\n")
  output.write_string(
    "before-output-chars: " + self.before_output_length.to_string() + "\n",
  )
  output.write_string(
    "after-output-chars: " + self.after_output_length.to_string(),
  )
  for change in self.changed {
    output.write_string(
      "\nchange " +
      change.sensitivity.label() +
      " span=" +
      change.span.start.to_string() +
      ":" +
      change.span.end.to_string() +
      " " +
      change.before.label() +
      " -> " +
      change.after.label(),
    )
  }
  output.to_string()
}
