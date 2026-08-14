///|
/// Sensitivity class assigned to a discovered span.
pub enum Sensitivity {
  Email
  IPv4
  PaymentCard
  Credential
  Custom(String)
} derive(Eq, @debug.Debug)

///|
pub fn Sensitivity::label(self : Sensitivity) -> String {
  match self {
    Email => "email"
    IPv4 => "ipv4"
    PaymentCard => "payment-card"
    Credential => "credential"
    Custom(value) => "custom:" + value
  }
}

///|
pub fn sensitivity_from_label(value : String) -> Sensitivity? {
  let normalized = ascii_lower_text(value.trim().to_owned())
  match normalized {
    "email" => Some(Email)
    "ipv4" => Some(IPv4)
    "payment-card" | "card" => Some(PaymentCard)
    "credential" | "secret" => Some(Credential)
    _ =>
      if normalized.has_prefix("custom:") && normalized.length() > 7 {
        Some(Custom(normalized[7:].to_owned()))
      } else {
        None
      }
  }
}

///|
pub enum Confidence {
  Low
  Medium
  High
} derive(Eq, @debug.Debug)

///|
pub fn Confidence::label(self : Confidence) -> String {
  match self {
    Low => "low"
    Medium => "medium"
    High => "high"
  }
}

///|
pub struct Span {
  start : Int
  end : Int
} derive(Eq, @debug.Debug)

///|
pub fn Span::new(start : Int, end : Int) -> Result[Span, Diagnostic] {
  if start < 0 {
    Err(
      Diagnostic::new(
        "span.start.invalid",
        "span.start",
        "span start must not be negative",
        "zero or greater",
        start.to_string(),
      ),
    )
  } else if end <= start {
    Err(
      Diagnostic::new(
        "span.end.invalid",
        "span.end",
        "span end must be greater than start",
        "greater than " + start.to_string(),
        end.to_string(),
      ),
    )
  } else {
    Ok({ start, end })
  }
}

///|
fn trusted_span(start : Int, end : Int) -> Span {
  { start, end }
}

///|
pub fn Span::start(self : Span) -> Int {
  self.start
}

///|
pub fn Span::end(self : Span) -> Int {
  self.end
}

///|
pub fn Span::length(self : Span) -> Int {
  self.end - self.start
}

///|
pub fn Span::overlaps(self : Span, other : Span) -> Bool {
  self.start < other.end && other.start < self.end
}

///|
pub fn Span::contains(self : Span, offset : Int) -> Bool {
  offset >= self.start && offset < self.end
}

///|
pub struct Finding {
  span : Span
  sensitivity : Sensitivity
  detector : String
  confidence : Confidence
  priority : Int
  value : String
} derive(Eq, @debug.Debug)

///|
fn make_finding(
  source : String,
  start : Int,
  end : Int,
  sensitivity : Sensitivity,
  detector : String,
  confidence : Confidence,
  priority : Int,
) -> Finding {
  {
    span: trusted_span(start, end),
    sensitivity,
    detector,
    confidence,
    priority,
    value: text_slice(source, start, end),
  }
}

///|
pub fn Finding::span(self : Finding) -> Span {
  self.span
}

///|
pub fn Finding::sensitivity(self : Finding) -> Sensitivity {
  self.sensitivity
}

///|
pub fn Finding::detector(self : Finding) -> String {
  self.detector
}

///|
pub fn Finding::confidence(self : Finding) -> Confidence {
  self.confidence
}

///|
pub fn Finding::priority(self : Finding) -> Int {
  self.priority
}

///|
/// Returns matched source text. Never include it in an audit log.
pub fn Finding::matched_text(self : Finding) -> String {
  self.value
}

///|
pub struct DictionaryTerm {
  name : String
  value : String
  case_sensitive : Bool
  whole_word : Bool
  priority : Int
} derive(Eq, @debug.Debug)

///|
pub fn DictionaryTerm::new(
  name : String,
  value : String,
  case_sensitive? : Bool = true,
  whole_word? : Bool = false,
  priority? : Int = 60,
) -> Result[DictionaryTerm, Diagnostic] {
  if name.trim().is_empty() {
    Err(
      Diagnostic::new(
        "dictionary.name.empty", "dictionary.name", "dictionary term name is empty",
        "non-empty name", "empty",
      ),
    )
  } else if value.is_empty() {
    Err(
      Diagnostic::new(
        "dictionary.value.empty", "dictionary.value", "dictionary term value is empty",
        "non-empty value", "empty",
      ),
    )
  } else if value.length() > 256 {
    Err(
      Diagnostic::new(
        "dictionary.value.limit",
        "dictionary.value",
        "dictionary term exceeds the safety limit",
        "at most 256 characters",
        value.length().to_string(),
      ),
    )
  } else if priority < 0 || priority > 1000 {
    Err(
      Diagnostic::new(
        "dictionary.priority.invalid",
        "dictionary.priority",
        "dictionary priority is outside the supported range",
        "0 through 1000",
        priority.to_string(),
      ),
    )
  } else {
    Ok({
      name: name.trim().to_owned(),
      value,
      case_sensitive,
      whole_word,
      priority,
    })
  }
}

///|
pub fn DictionaryTerm::name(self : DictionaryTerm) -> String {
  self.name
}

///|
pub fn DictionaryTerm::value(self : DictionaryTerm) -> String {
  self.value
}

///|
pub fn DictionaryTerm::case_sensitive(self : DictionaryTerm) -> Bool {
  self.case_sensitive
}

///|
pub fn DictionaryTerm::whole_word(self : DictionaryTerm) -> Bool {
  self.whole_word
}

///|
pub fn DictionaryTerm::priority(self : DictionaryTerm) -> Int {
  self.priority
}
