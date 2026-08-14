///|
test "corpus evaluation reports exact detector matches" {
  let one_source = "mail=a@example.com"
  let two_source = "ip=10.0.0.1"
  let one = EvaluationCase::new("email", one_source, [
    GroundTruth::new(one_source, 5, 18, Email).unwrap(),
  ]).unwrap()
  let two = EvaluationCase::new("ip", two_source, [
    GroundTruth::new(two_source, 3, 11, IPv4).unwrap(),
  ]).unwrap()
  let report = evaluate_corpus([one, two]).unwrap()
  assert_true(report.is_exact())
  assert_eq(report.true_positive(), 2)
  assert_eq(report.precision_permille(), 1000)
  assert_eq(report.recall_permille(), 1000)
}

///|
test "corpus evaluation distinguishes false positives and negatives" {
  let source = "mail=a@example.com ip=10.0.0.1"
  let expected = [GroundTruth::new(source, 5, 18, IPv4).unwrap()]
  let case = EvaluationCase::new("mismatch", source, expected).unwrap()
  let report = evaluate_corpus([case]).unwrap()
  assert_eq(report.true_positive(), 0)
  assert_eq(report.false_positive(), 2)
  assert_eq(report.false_negative(), 1)
  assert_eq(report.precision_permille(), 0)
  assert_eq(report.recall_permille(), 0)
}

///|
test "disabled detector changes corpus recall" {
  let source = "10.0.0.1"
  let case = EvaluationCase::new("ipv4", source, [
    GroundTruth::new(source, 0, 8, IPv4).unwrap(),
  ]).unwrap()
  let report = evaluate_corpus(
    [case],
    config=ScanConfig::default().with_ipv4(false),
  ).unwrap()
  assert_eq(report.false_negative(), 1)
  assert_eq(report.false_positive(), 0)
}

///|
test "evaluation validates truth bounds and duplicate cases" {
  assert_eq(
    GroundTruth::new("abc", 0, 4, Email).unwrap_err().code(),
    "evaluation.span.outside",
  )
  let case = EvaluationCase::new("same", "clean", []).unwrap()
  assert_eq(
    evaluate_corpus([case, case]).unwrap_err().code(),
    "evaluation.case.duplicate",
  )
}

///|
test "evaluation rejects duplicate expected finding" {
  let source = "a@example.com"
  let truth = GroundTruth::new(source, 0, 13, Email).unwrap()
  assert_eq(
    EvaluationCase::new("duplicate", source, [truth, truth]).unwrap_err().code(),
    "evaluation.truth.duplicate",
  )
}

///|
test "evaluation text report contains aggregate and case evidence" {
  let report = evaluate_corpus([
      EvaluationCase::new("clean", "nothing", []).unwrap(),
    ])
    .unwrap()
    .render_text()
  assert_true(report.contains("precision-permille: 1000"))
  assert_true(report.contains("case clean tp=0 fp=0 fn=0"))
}
