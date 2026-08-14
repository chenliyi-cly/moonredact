///|
test "scan returns ordered non-overlapping findings" {
  let result = scan("email=a@example.com ip=10.2.3.4 card=4111111111111111").unwrap()
  let findings = result.findings()
  assert_eq(findings.length(), 3)
  assert_eq(findings[0].sensitivity().label(), "email")
  assert_eq(findings[1].sensitivity().label(), "ipv4")
  assert_eq(findings[2].sensitivity().label(), "payment-card")
}

///|
test "exact allowlist suppresses without removing unrelated findings" {
  let config = ScanConfig::default().with_allowlist(["127.0.0.1"]).unwrap()
  let result = scan("local=127.0.0.1 remote=10.0.0.8", config~).unwrap()
  assert_eq(result.findings().length(), 1)
  assert_eq(result.findings()[0].matched_text(), "10.0.0.8")
  assert_eq(result.suppressed().length(), 1)
  assert_eq(result.suppressed()[0].reason().label(), "allowlisted")
}

///|
test "higher-priority credential wins an overlapping dictionary finding" {
  let term = DictionaryTerm::new("known-secret", "abc-123", priority=900).unwrap()
  let config = ScanConfig::default().with_dictionary([term]).unwrap()
  let result = scan("password=abc-123", config~).unwrap()
  assert_eq(result.findings().length(), 1)
  assert_eq(result.findings()[0].sensitivity().label(), "custom:known-secret")
  assert_eq(result.suppressed().length(), 1)
  assert_eq(
    result.suppressed()[0].reason().label(),
    "overlapped-by:dictionary:known-secret",
  )
}

///|
test "scan enforces configured input bound" {
  let config = ScanConfig::default().with_max_input_chars(4).unwrap()
  assert_eq(scan("12345", config~).unwrap_err().code(), "scan.input.limit")
}

///|
test "detectors can be disabled independently" {
  let config = ScanConfig::default().with_email(false).with_ipv4(false)
  assert_eq(
    scan("a@example.com 10.0.0.1", config~).unwrap().findings().length(),
    0,
  )
}
