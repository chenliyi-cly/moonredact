///|
pub struct GroundTruth {
  span : Span
  sensitivity : Sensitivity
} derive(Eq, @debug.Debug)

///|
pub fn GroundTruth::new(
  source : String,
  start : Int,
  end : Int,
  sensitivity : Sensitivity,
) -> Result[GroundTruth, Diagnostic] {
  let span = match Span::new(start, end) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  if end > source.length() {
    Err(
      Diagnostic::new(
        "evaluation.span.outside",
        "ground-truth.span",
        "expected span extends beyond source text",
        "end at most " + source.length().to_string(),
        end.to_string(),
      ),
    )
  } else {
    Ok({ span, sensitivity })
  }
}

///|
pub fn GroundTruth::span(self : GroundTruth) -> Span {
  self.span
}

///|
pub fn GroundTruth::sensitivity(self : GroundTruth) -> Sensitivity {
  self.sensitivity
}

///|
pub struct EvaluationCase {
  name : String
  source : String
  expected : Array[GroundTruth]
} derive(Eq, @debug.Debug)

///|
fn same_truth(left : GroundTruth, right : GroundTruth) -> Bool {
  left.span == right.span && left.sensitivity == right.sensitivity
}

///|
pub fn EvaluationCase::new(
  name : String,
  source : String,
  expected : Array[GroundTruth],
) -> Result[EvaluationCase, Diagnostic] {
  if name.trim().is_empty() {
    return Err(
      Diagnostic::new(
        "evaluation.case.name.empty", "case.name", "evaluation case name is empty",
        "non-empty unique name", "empty",
      ),
    )
  }
  if name.length() > 256 {
    return Err(
      Diagnostic::new(
        "evaluation.case.name.limit",
        "case.name",
        "evaluation case name exceeds the safety limit",
        "at most 256 characters",
        name.length().to_string(),
      ),
    )
  }
  if expected.length() > 10000 {
    return Err(
      Diagnostic::new(
        "evaluation.truth.limit",
        "case.expected",
        "case has too many expected findings",
        "at most 10000",
        expected.length().to_string(),
      ),
    )
  }
  for index, truth in expected {
    if truth.span.end > source.length() {
      return Err(
        Diagnostic::new(
          "evaluation.span.outside",
          "case.expected[" + index.to_string() + "]",
          "expected span extends beyond source text",
          "end at most " + source.length().to_string(),
          truth.span.end.to_string(),
        ),
      )
    }
    for earlier = 0; earlier < index; earlier = earlier + 1 {
      if same_truth(expected[earlier], truth) {
        return Err(
          Diagnostic::new(
            "evaluation.truth.duplicate",
            "case.expected[" + index.to_string() + "]",
            "expected finding is duplicated",
            "unique span and class",
            truth.sensitivity.label(),
          ),
        )
      }
    }
  }
  Ok({ name: name.trim().to_owned(), source, expected: expected.copy() })
}

///|
pub fn EvaluationCase::name(self : EvaluationCase) -> String {
  self.name
}

///|
pub fn EvaluationCase::expected(self : EvaluationCase) -> Array[GroundTruth] {
  self.expected.copy()
}

///|
pub struct ClassEvaluation {
  sensitivity : String
  true_positive : Int
  false_positive : Int
  false_negative : Int
} derive(Eq, @debug.Debug)

///|
pub fn ClassEvaluation::sensitivity(self : ClassEvaluation) -> String {
  self.sensitivity
}

///|
pub fn ClassEvaluation::true_positive(self : ClassEvaluation) -> Int {
  self.true_positive
}

///|
pub fn ClassEvaluation::false_positive(self : ClassEvaluation) -> Int {
  self.false_positive
}

///|
pub fn ClassEvaluation::false_negative(self : ClassEvaluation) -> Int {
  self.false_negative
}

///|
fn update_class_evaluation(
  values : Array[ClassEvaluation],
  sensitivity : String,
  tp : Int,
  fp : Int,
  fn_count : Int,
) -> Unit {
  for index = 0; index < values.length(); index = index + 1 {
    if values[index].sensitivity == sensitivity {
      values[index] = {
        sensitivity,
        true_positive: values[index].true_positive + tp,
        false_positive: values[index].false_positive + fp,
        false_negative: values[index].false_negative + fn_count,
      }
      return
    }
  }
  values.push({
    sensitivity,
    true_positive: tp,
    false_positive: fp,
    false_negative: fn_count,
  })
}

///|
fn finding_matches_truth(finding : Finding, truth : GroundTruth) -> Bool {
  finding.span == truth.span && finding.sensitivity == truth.sensitivity
}

///|
pub struct CaseEvaluation {
  name : String
  predicted : Int
  expected : Int
  true_positive : Int
  false_positive : Int
  false_negative : Int
} derive(Eq, @debug.Debug)

///|
pub fn CaseEvaluation::name(self : CaseEvaluation) -> String {
  self.name
}

///|
pub fn CaseEvaluation::is_exact(self : CaseEvaluation) -> Bool {
  self.false_positive == 0 && self.false_negative == 0
}

///|
pub fn CaseEvaluation::true_positive(self : CaseEvaluation) -> Int {
  self.true_positive
}

///|
pub fn CaseEvaluation::false_positive(self : CaseEvaluation) -> Int {
  self.false_positive
}

///|
pub fn CaseEvaluation::false_negative(self : CaseEvaluation) -> Int {
  self.false_negative
}

///|
pub struct CorpusEvaluation {
  cases : Array[CaseEvaluation]
  classes : Array[ClassEvaluation]
  true_positive : Int
  false_positive : Int
  false_negative : Int
} derive(Eq, @debug.Debug)

///|
fn evaluate_case(
  case : EvaluationCase,
  config : ScanConfig,
  classes : Array[ClassEvaluation],
) -> Result[CaseEvaluation, Diagnostic] {
  let scanned = match scan(case.source, config~) {
    Ok(value) => value
    Err(error) =>
      return Err(
        Diagnostic::new(
          error.code(),
          "case." + case.name + "." + error.location(),
          error.message(),
          error.expected(),
          error.actual(),
        ),
      )
  }
  let used = Array::make(case.expected.length(), false)
  let mut true_positive = 0
  let mut false_positive = 0
  for finding in scanned.findings {
    let mut matched = -1
    for index, truth in case.expected {
      if !used[index] && finding_matches_truth(finding, truth) && matched < 0 {
        matched = index
      }
    }
    if matched >= 0 {
      used[matched] = true
      true_positive = true_positive + 1
      update_class_evaluation(classes, finding.sensitivity.label(), 1, 0, 0)
    } else {
      false_positive = false_positive + 1
      update_class_evaluation(classes, finding.sensitivity.label(), 0, 1, 0)
    }
  }
  let mut false_negative = 0
  for index, truth in case.expected {
    if !used[index] {
      false_negative = false_negative + 1
      update_class_evaluation(classes, truth.sensitivity.label(), 0, 0, 1)
    }
  }
  Ok({
    name: case.name,
    predicted: scanned.findings.length(),
    expected: case.expected.length(),
    true_positive,
    false_positive,
    false_negative,
  })
}

///|
/// Evaluate exact span-and-class matches over a labeled in-memory corpus.
pub fn evaluate_corpus(
  cases : Array[EvaluationCase],
  config? : ScanConfig = ScanConfig::default(),
) -> Result[CorpusEvaluation, Diagnostic] {
  if cases.length() > 1000 {
    return Err(
      Diagnostic::new(
        "evaluation.case.limit",
        "corpus",
        "corpus has too many cases",
        "at most 1000 cases",
        cases.length().to_string(),
      ),
    )
  }
  let names : Array[String] = []
  let results : Array[CaseEvaluation] = []
  let classes : Array[ClassEvaluation] = []
  let mut tp = 0
  let mut fp = 0
  let mut fn_count = 0
  for case in cases {
    if contains_exact(names, case.name) {
      return Err(
        Diagnostic::new(
          "evaluation.case.duplicate",
          "corpus." + case.name,
          "case name is duplicated",
          "unique case name",
          case.name,
        ),
      )
    }
    names.push(case.name)
    let result = match evaluate_case(case, config, classes) {
      Ok(value) => value
      Err(error) => return Err(error)
    }
    tp = tp + result.true_positive
    fp = fp + result.false_positive
    fn_count = fn_count + result.false_negative
    results.push(result)
  }
  Ok({
    cases: results,
    classes,
    true_positive: tp,
    false_positive: fp,
    false_negative: fn_count,
  })
}

///|
pub fn CorpusEvaluation::cases(
  self : CorpusEvaluation,
) -> Array[CaseEvaluation] {
  self.cases.copy()
}

///|
pub fn CorpusEvaluation::classes(
  self : CorpusEvaluation,
) -> Array[ClassEvaluation] {
  self.classes.copy()
}

///|
pub fn CorpusEvaluation::true_positive(self : CorpusEvaluation) -> Int {
  self.true_positive
}

///|
pub fn CorpusEvaluation::false_positive(self : CorpusEvaluation) -> Int {
  self.false_positive
}

///|
pub fn CorpusEvaluation::false_negative(self : CorpusEvaluation) -> Int {
  self.false_negative
}

///|
fn ratio_permille(numerator : Int, denominator : Int) -> Int {
  if denominator == 0 {
    1000
  } else {
    numerator * 1000 / denominator
  }
}

///|
pub fn CorpusEvaluation::precision_permille(self : CorpusEvaluation) -> Int {
  ratio_permille(self.true_positive, self.true_positive + self.false_positive)
}

///|
pub fn CorpusEvaluation::recall_permille(self : CorpusEvaluation) -> Int {
  ratio_permille(self.true_positive, self.true_positive + self.false_negative)
}

///|
pub fn CorpusEvaluation::is_exact(self : CorpusEvaluation) -> Bool {
  self.false_positive == 0 && self.false_negative == 0
}

///|
pub fn CorpusEvaluation::render_text(self : CorpusEvaluation) -> String {
  let output = StringBuilder::new()
  output.write_string("MoonRedact corpus evaluation\n")
  output.write_string("cases: " + self.cases.length().to_string() + "\n")
  output.write_string("true-positive: " + self.true_positive.to_string() + "\n")
  output.write_string(
    "false-positive: " + self.false_positive.to_string() + "\n",
  )
  output.write_string(
    "false-negative: " + self.false_negative.to_string() + "\n",
  )
  output.write_string(
    "precision-permille: " + self.precision_permille().to_string() + "\n",
  )
  output.write_string(
    "recall-permille: " + self.recall_permille().to_string() + "\n",
  )
  for case in self.cases {
    output.write_string(
      "case " +
      case.name +
      " tp=" +
      case.true_positive.to_string() +
      " fp=" +
      case.false_positive.to_string() +
      " fn=" +
      case.false_negative.to_string() +
      "\n",
    )
  }
  output.to_string().trim().to_owned()
}
