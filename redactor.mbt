///|
pub struct RedactionDecision {
  span : Span
  sensitivity : Sensitivity
  detector : String
  action : RedactionAction
  replacement : String
} derive(Eq, @debug.Debug)

///|
pub fn RedactionDecision::span(self : RedactionDecision) -> Span {
  self.span
}

///|
pub fn RedactionDecision::sensitivity(self : RedactionDecision) -> Sensitivity {
  self.sensitivity
}

///|
pub fn RedactionDecision::detector(self : RedactionDecision) -> String {
  self.detector
}

///|
pub fn RedactionDecision::action(self : RedactionDecision) -> RedactionAction {
  self.action
}

///|
pub fn RedactionDecision::replacement(self : RedactionDecision) -> String {
  self.replacement
}

///|
pub struct RedactionResult {
  sanitized : String
  scan_result : ScanResult
  decisions : Array[RedactionDecision]
} derive(Eq, @debug.Debug)

///|
pub fn RedactionResult::sanitized_text(self : RedactionResult) -> String {
  self.sanitized
}

///|
pub fn RedactionResult::scan_result(self : RedactionResult) -> ScanResult {
  self.scan_result
}

///|
pub fn RedactionResult::decisions(
  self : RedactionResult,
) -> Array[RedactionDecision] {
  self.decisions.copy()
}

///|
fn mask_text(source : String, visible : Int) -> String {
  let chars = source.to_array()
  let mut maskable = 0
  for char in chars {
    if is_ascii_alphanumeric(char) {
      maskable = maskable + 1
    }
  }
  let hidden = if maskable > visible { maskable - visible } else { 0 }
  let output = StringBuilder::new()
  let mut seen = 0
  for char in chars {
    if is_ascii_alphanumeric(char) {
      if seen < hidden {
        output.write_char('*')
      } else {
        output.write_char(char)
      }
      seen = seen + 1
    } else {
      output.write_char(char)
    }
  }
  output.to_string()
}

///|
fn replacement_for(
  finding : Finding,
  action : RedactionAction,
  salt : String,
) -> String {
  match action {
    Keep => finding.value
    Mask(visible) => mask_text(finding.value, visible)
    Remove => ""
    Token(prefix) => prefix + stable_text_hash(finding.value, salt)
  }
}

///|
/// Scan and redact one text without mutating or retaining external state.
pub fn redact(
  source : String,
  config? : ScanConfig = ScanConfig::default(),
  policy? : RedactionPolicy = RedactionPolicy::balanced(),
) -> Result[RedactionResult, Diagnostic] {
  let scanned = match scan(source, config~) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let output = StringBuilder::new()
  let decisions : Array[RedactionDecision] = []
  let mut cursor = 0
  for finding in scanned.findings {
    output.write_string(text_slice(source, cursor, finding.span.start))
    let action = policy.action_for(finding.sensitivity)
    let replacement = replacement_for(finding, action, policy.token_salt)
    output.write_string(replacement)
    decisions.push({
      span: finding.span,
      sensitivity: finding.sensitivity,
      detector: finding.detector,
      action,
      replacement,
    })
    cursor = finding.span.end
  }
  output.write_string(text_slice(source, cursor, source.length()))
  Ok({ sanitized: output.to_string(), scan_result: scanned, decisions })
}
