///|
pub struct CountEntry {
  label : String
  count : Int
} derive(Eq, @debug.Debug)

///|
pub fn CountEntry::label(self : CountEntry) -> String {
  self.label
}

///|
pub fn CountEntry::count(self : CountEntry) -> Int {
  self.count
}

///|
fn increment_count(entries : Array[CountEntry], label : String) -> Unit {
  for index = 0; index < entries.length(); index = index + 1 {
    if entries[index].label == label {
      entries[index] = { label, count: entries[index].count + 1 }
      return
    }
  }
  entries.push({ label, count: 1 })
}

///|
fn sort_counts(entries : Array[CountEntry]) -> Array[CountEntry] {
  let order = ["credential", "payment-card", "email", "ipv4"]
  let result : Array[CountEntry] = []
  for label in order {
    for entry in entries {
      if entry.label == label {
        result.push(entry)
      }
    }
  }
  for entry in entries {
    if !contains_exact(order, entry.label) {
      result.push(entry)
    }
  }
  result
}

///|
pub struct AuditReport {
  input_length : Int
  output_length : Int
  candidates : Int
  accepted : Int
  suppressed : Int
  changed : Int
  kept : Int
  by_class : Array[CountEntry]
  by_action : Array[CountEntry]
  by_suppression : Array[CountEntry]
} derive(Eq, @debug.Debug)

///|
pub fn audit(result : RedactionResult) -> AuditReport {
  let classes : Array[CountEntry] = []
  let actions : Array[CountEntry] = []
  let suppressions : Array[CountEntry] = []
  let mut changed = 0
  let mut kept = 0
  for decision in result.decisions {
    increment_count(classes, decision.sensitivity.label())
    increment_count(actions, decision.action.label())
    if decision.action is Keep {
      kept = kept + 1
    } else {
      changed = changed + 1
    }
  }
  for suppressed in result.scan_result.suppressed {
    increment_count(suppressions, suppressed.reason.label())
  }
  {
    input_length: result.scan_result.input_length,
    output_length: result.sanitized.length(),
    candidates: result.scan_result.candidate_count,
    accepted: result.scan_result.findings.length(),
    suppressed: result.scan_result.suppressed.length(),
    changed,
    kept,
    by_class: sort_counts(classes),
    by_action: actions,
    by_suppression: suppressions,
  }
}

///|
pub fn AuditReport::input_length(self : AuditReport) -> Int {
  self.input_length
}

///|
pub fn AuditReport::output_length(self : AuditReport) -> Int {
  self.output_length
}

///|
pub fn AuditReport::candidate_count(self : AuditReport) -> Int {
  self.candidates
}

///|
pub fn AuditReport::accepted_count(self : AuditReport) -> Int {
  self.accepted
}

///|
pub fn AuditReport::suppressed_count(self : AuditReport) -> Int {
  self.suppressed
}

///|
pub fn AuditReport::changed_count(self : AuditReport) -> Int {
  self.changed
}

///|
pub fn AuditReport::kept_count(self : AuditReport) -> Int {
  self.kept
}

///|
pub fn AuditReport::class_counts(self : AuditReport) -> Array[CountEntry] {
  self.by_class.copy()
}

///|
pub fn AuditReport::action_counts(self : AuditReport) -> Array[CountEntry] {
  self.by_action.copy()
}

///|
fn render_count_lines(
  output : StringBuilder,
  title : String,
  entries : Array[CountEntry],
) -> Unit {
  output.write_string(title + ":")
  if entries.is_empty() {
    output.write_string(" none\n")
    return
  }
  output.write_char('\n')
  for entry in entries {
    output.write_string(
      "  " + entry.label + ": " + entry.count.to_string() + "\n",
    )
  }
}

///|
pub fn AuditReport::render_text(self : AuditReport) -> String {
  let output = StringBuilder::new()
  output.write_string("MoonRedact audit\n")
  output.write_string("input-chars: " + self.input_length.to_string() + "\n")
  output.write_string("output-chars: " + self.output_length.to_string() + "\n")
  output.write_string("candidates: " + self.candidates.to_string() + "\n")
  output.write_string("accepted: " + self.accepted.to_string() + "\n")
  output.write_string("suppressed: " + self.suppressed.to_string() + "\n")
  output.write_string("changed: " + self.changed.to_string() + "\n")
  output.write_string("kept: " + self.kept.to_string() + "\n")
  render_count_lines(output, "classes", self.by_class)
  render_count_lines(output, "actions", self.by_action)
  render_count_lines(output, "suppressions", self.by_suppression)
  output.to_string()
}

///|
fn json_escape(source : String) -> String {
  let output = StringBuilder::new()
  for char in source {
    match char {
      '"' => output.write_string("\\\"")
      '\\' => output.write_string("\\\\")
      '\n' => output.write_string("\\n")
      '\r' => output.write_string("\\r")
      '\t' => output.write_string("\\t")
      _ =>
        if char.to_int() < 32 {
          output.write_char('?')
        } else {
          output.write_char(char)
        }
    }
  }
  output.to_string()
}

///|
fn render_count_json(entries : Array[CountEntry]) -> String {
  let output = StringBuilder::new()
  output.write_char('[')
  for index, entry in entries {
    if index > 0 {
      output.write_char(',')
    }
    output.write_string(
      "{\"label\":\"" +
      json_escape(entry.label) +
      "\",\"count\":" +
      entry.count.to_string() +
      "}",
    )
  }
  output.write_char(']')
  output.to_string()
}

///|
pub fn AuditReport::render_json(self : AuditReport) -> String {
  "{\"input_chars\":" +
  self.input_length.to_string() +
  ",\"output_chars\":" +
  self.output_length.to_string() +
  ",\"candidates\":" +
  self.candidates.to_string() +
  ",\"accepted\":" +
  self.accepted.to_string() +
  ",\"suppressed\":" +
  self.suppressed.to_string() +
  ",\"changed\":" +
  self.changed.to_string() +
  ",\"kept\":" +
  self.kept.to_string() +
  ",\"classes\":" +
  render_count_json(self.by_class) +
  ",\"actions\":" +
  render_count_json(self.by_action) +
  ",\"suppressions\":" +
  render_count_json(self.by_suppression) +
  "}"
}
