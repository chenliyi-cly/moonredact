///|
pub struct SourcePosition {
  offset : Int
  line : Int
  column : Int
} derive(Eq, @debug.Debug)

///|
pub fn SourcePosition::offset(self : SourcePosition) -> Int {
  self.offset
}

///|
pub fn SourcePosition::line(self : SourcePosition) -> Int {
  self.line
}

///|
pub fn SourcePosition::column(self : SourcePosition) -> Int {
  self.column
}

///|
pub fn SourcePosition::render(self : SourcePosition) -> String {
  self.line.to_string() + ":" + self.column.to_string()
}

///|
pub struct SourceIndex {
  source_length : Int
  line_starts : Array[Int]
} derive(Eq, @debug.Debug)

///|
pub fn SourceIndex::new(source : String) -> SourceIndex {
  let starts = [0]
  let chars = source.to_array()
  for index = 0; index < chars.length(); index = index + 1 {
    if chars[index] == '\n' {
      starts.push(index + 1)
    }
  }
  { source_length: source.length(), line_starts: starts }
}

///|
pub fn SourceIndex::line_count(self : SourceIndex) -> Int {
  self.line_starts.length()
}

///|
fn line_for_offset(starts : Array[Int], offset : Int) -> Int {
  let mut low = 0
  let mut high = starts.length()
  while low + 1 < high {
    let middle = low + (high - low) / 2
    if starts[middle] <= offset {
      low = middle
    } else {
      high = middle
    }
  }
  low
}

///|
pub fn SourceIndex::position(
  self : SourceIndex,
  offset : Int,
) -> Result[SourcePosition, Diagnostic] {
  if offset < 0 || offset > self.source_length {
    return Err(
      Diagnostic::new(
        "location.offset.invalid",
        "offset",
        "source offset is outside the indexed text",
        "0 through " + self.source_length.to_string(),
        offset.to_string(),
      ),
    )
  }
  let line_index = line_for_offset(self.line_starts, offset)
  Ok({
    offset,
    line: line_index + 1,
    column: offset - self.line_starts[line_index] + 1,
  })
}

///|
pub struct LocatedFinding {
  finding : Finding
  start : SourcePosition
  end : SourcePosition
} derive(Eq, @debug.Debug)

///|
pub fn LocatedFinding::finding(self : LocatedFinding) -> Finding {
  self.finding
}

///|
pub fn LocatedFinding::start(self : LocatedFinding) -> SourcePosition {
  self.start
}

///|
pub fn LocatedFinding::end(self : LocatedFinding) -> SourcePosition {
  self.end
}

///|
pub fn LocatedFinding::render_location(self : LocatedFinding) -> String {
  self.start.render() + "-" + self.end.render()
}

///|
pub fn locate_findings(
  source : String,
  result : ScanResult,
) -> Result[Array[LocatedFinding], Diagnostic] {
  if source.length() != result.input_length {
    return Err(
      Diagnostic::new(
        "location.source.mismatch",
        "source",
        "source length does not match scan result",
        result.input_length.to_string(),
        source.length().to_string(),
      ),
    )
  }
  let index = SourceIndex::new(source)
  let located : Array[LocatedFinding] = []
  for finding in result.findings {
    let start = match index.position(finding.span.start) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    let end = match index.position(finding.span.end) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    located.push({ finding, start, end })
  }
  Ok(located)
}

///|
pub struct LineSummary {
  line : Int
  finding_count : Int
  classes : Array[CountEntry]
} derive(Eq, @debug.Debug)

///|
pub fn LineSummary::line(self : LineSummary) -> Int {
  self.line
}

///|
pub fn LineSummary::finding_count(self : LineSummary) -> Int {
  self.finding_count
}

///|
pub fn LineSummary::class_counts(self : LineSummary) -> Array[CountEntry] {
  self.classes.copy()
}

///|
pub fn summarize_lines(findings : Array[LocatedFinding]) -> Array[LineSummary] {
  let summaries : Array[LineSummary] = []
  for located in findings {
    let line = located.start.line
    let mut found = -1
    for index, summary in summaries {
      if summary.line == line {
        found = index
      }
    }
    if found < 0 {
      summaries.push({
        line,
        finding_count: 1,
        classes: [{ label: located.finding.sensitivity.label(), count: 1 }],
      })
    } else {
      let classes = summaries[found].classes.copy()
      increment_count(classes, located.finding.sensitivity.label())
      summaries[found] = {
        line,
        finding_count: summaries[found].finding_count + 1,
        classes,
      }
    }
  }
  summaries
}
