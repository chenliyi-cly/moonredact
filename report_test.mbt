///|
test "audit report counts accepted, changed, and suppressed findings" {
  let config = ScanConfig::default().with_allowlist(["127.0.0.1"]).unwrap()
  let result = redact(
    "mail=a@example.com local=127.0.0.1 password=hidden",
    config~,
  ).unwrap()
  let report = audit(result)
  assert_eq(report.candidate_count(), 3)
  assert_eq(report.accepted_count(), 2)
  assert_eq(report.suppressed_count(), 1)
  assert_eq(report.changed_count(), 2)
  assert_eq(report.class_counts().length(), 2)
}

///|
test "text audit contains no matched sensitive values" {
  let report = audit(redact("password=super-secret a@example.com").unwrap()).render_text()
  assert_true(!report.contains("super-secret"))
  assert_true(!report.contains("a@example.com"))
  assert_true(report.contains("credential: 1"))
}

///|
test "JSON audit is compact and deterministic" {
  let report = audit(redact("a@example.com").unwrap()).render_json()
  assert_eq(
    report, "{\"input_chars\":13,\"output_chars\":13,\"candidates\":1,\"accepted\":1,\"suppressed\":0,\"changed\":1,\"kept\":0,\"classes\":[{\"label\":\"email\",\"count\":1}],\"actions\":[{\"label\":\"mask:0\",\"count\":1}],\"suppressions\":[]}",
  )
}

///|
test "batch redaction aggregates named inputs" {
  let inputs = [
    NamedInput::new("one", "a@example.com").unwrap(),
    NamedInput::new("two", "10.0.0.1").unwrap(),
  ]
  let result = redact_batch(inputs).unwrap()
  assert_eq(result.input_count(), 2)
  assert_eq(result.finding_count(), 2)
  assert_eq(result.changed_count(), 2)
  assert_eq(result.items()[0].name(), "one")
}

///|
test "batch rejects duplicate names and reports item scan failures" {
  let same = NamedInput::new("same", "x").unwrap()
  assert_eq(
    redact_batch([same, same]).unwrap_err().code(),
    "batch.name.duplicate",
  )
  let profile = RedactionProfile::new(
    ScanConfig::default().with_max_input_chars(2).unwrap(),
    RedactionPolicy::balanced(),
  )
  let error = redact_batch([NamedInput::new("long", "abc").unwrap()], profile~).unwrap_err()
  assert_eq(error.location(), "batch.long.input")
}

///|
test "residual verification catches intentionally kept data" {
  let kept = redact("a@example.com", policy=RedactionPolicy::passthrough()).unwrap()
  assert_true(!verify_sanitized(kept).unwrap().is_clean())
  let removed = redact("a@example.com", policy=RedactionPolicy::strict()).unwrap()
  assert_true(verify_sanitized(removed).unwrap().is_clean())
}
