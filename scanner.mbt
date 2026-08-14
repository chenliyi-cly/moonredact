///|
pub enum SuppressionReason {
  Allowlisted
  Overlapped(String)
} derive(Eq, @debug.Debug)

///|
pub fn SuppressionReason::label(self : SuppressionReason) -> String {
  match self {
    Allowlisted => "allowlisted"
    Overlapped(detector) => "overlapped-by:" + detector
  }
}

///|
pub struct SuppressedFinding {
  finding : Finding
  reason : SuppressionReason
} derive(Eq, @debug.Debug)

///|
pub fn SuppressedFinding::finding(self : SuppressedFinding) -> Finding {
  self.finding
}

///|
pub fn SuppressedFinding::reason(self : SuppressedFinding) -> SuppressionReason {
  self.reason
}

///|
pub struct ScanResult {
  input_length : Int
  candidate_count : Int
  findings : Array[Finding]
  suppressed : Array[SuppressedFinding]
} derive(Eq, @debug.Debug)

///|
pub fn ScanResult::input_length(self : ScanResult) -> Int {
  self.input_length
}

///|
pub fn ScanResult::candidate_count(self : ScanResult) -> Int {
  self.candidate_count
}

///|
pub fn ScanResult::findings(self : ScanResult) -> Array[Finding] {
  self.findings.copy()
}

///|
pub fn ScanResult::suppressed(self : ScanResult) -> Array[SuppressedFinding] {
  self.suppressed.copy()
}

///|
fn stronger_finding(left : Finding, right : Finding) -> Bool {
  if left.priority != right.priority {
    left.priority > right.priority
  } else if left.span.length() != right.span.length() {
    left.span.length() > right.span.length()
  } else {
    left.span.start < right.span.start
  }
}

///|
fn earlier_finding(left : Finding, right : Finding) -> Bool {
  if left.span.start != right.span.start {
    left.span.start < right.span.start
  } else if left.span.end != right.span.end {
    left.span.end < right.span.end
  } else {
    left.priority > right.priority
  }
}

///|
fn sort_findings(
  input : Array[Finding],
  precedes : (Finding, Finding) -> Bool,
) -> Array[Finding] {
  let result = input.copy()
  for index = 1; index < result.length(); index = index + 1 {
    let value = result[index]
    let mut cursor = index
    while cursor > 0 && precedes(value, result[cursor - 1]) {
      result[cursor] = result[cursor - 1]
      cursor = cursor - 1
    }
    result[cursor] = value
  }
  result
}

///|
fn exact_allowlisted(config : ScanConfig, finding : Finding) -> Bool {
  contains_exact(config.allowlist, finding.value)
}

///|
fn overlapping_winner(
  accepted : Array[Finding],
  candidate : Finding,
) -> Finding? {
  for winner in accepted {
    if winner.span.overlaps(candidate.span) {
      return Some(winner)
    }
  }
  None
}

///|
fn resolve_candidates(
  candidates : Array[Finding],
  config : ScanConfig,
) -> (Array[Finding], Array[SuppressedFinding]) {
  let ranked = sort_findings(candidates, stronger_finding)
  let accepted : Array[Finding] = []
  let suppressed : Array[SuppressedFinding] = []
  for candidate in ranked {
    if exact_allowlisted(config, candidate) {
      suppressed.push({ finding: candidate, reason: Allowlisted })
    } else {
      match overlapping_winner(accepted, candidate) {
        Some(winner) =>
          suppressed.push({
            finding: candidate,
            reason: Overlapped(winner.detector),
          })
        None => accepted.push(candidate)
      }
    }
  }
  (sort_findings(accepted, earlier_finding), suppressed)
}

///|
/// Scan one in-memory text and deterministically resolve overlapping findings.
pub fn scan(
  source : String,
  config? : ScanConfig = ScanConfig::default(),
) -> Result[ScanResult, Diagnostic] {
  if source.length() > config.max_input_chars {
    return Err(
      Diagnostic::new(
        "scan.input.limit",
        "input",
        "input exceeds the configured safety limit",
        "at most " + config.max_input_chars.to_string() + " characters",
        source.length().to_string(),
      ),
    )
  }
  let candidates = collect_candidates(source, config)
  let resolved = resolve_candidates(candidates, config)
  Ok({
    input_length: source.length(),
    candidate_count: candidates.length(),
    findings: resolved.0,
    suppressed: resolved.1,
  })
}
