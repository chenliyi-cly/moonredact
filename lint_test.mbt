///|
test "balanced policy has no lint errors" {
  let report = lint_policy(RedactionPolicy::balanced())
  assert_true(report.passes())
  assert_eq(report.error_count(), 0)
  assert_true(report.warning_count() >= 1)
  assert_true(report.render_text().contains("policy.token-salt.default"))
}

///|
test "strict policy passes and has zero action risk" {
  let report = lint_policy(RedactionPolicy::strict())
  assert_true(report.passes())
  assert_eq(report.risk_score(), 0)
  assert_true(report.info_count() >= 1)
}

///|
test "keep default produces credential and general exposure errors" {
  let report = lint_policy(RedactionPolicy::passthrough())
  assert_true(!report.passes())
  assert_true(report.error_count() >= 2)
  assert_eq(report.risk_score(), 500)
}

///|
test "same-priority conflicting rules are ambiguous" {
  let first = PolicyRule::new("email", Remove, priority=100).unwrap()
  let second = PolicyRule::new("email", Keep, priority=100).unwrap()
  let policy = RedactionPolicy::new(default_action=Remove, rules=[first, second]).unwrap()
  let report = lint_policy(policy)
  assert_true(
    report.issues().any(fn(issue) { issue.code() == "policy.rule.ambiguous" }),
  )
  assert_true(
    report.issues().any(fn(issue) { issue.code() == "policy.rule.shadowed" }),
  )
}

///|
test "lower-priority duplicate selector is shadowed" {
  let high = PolicyRule::new("ipv4", Remove, priority=200).unwrap()
  let low = PolicyRule::new("ipv4", Keep, priority=100).unwrap()
  let report = lint_policy(
    RedactionPolicy::new(default_action=Remove, rules=[high, low]).unwrap(),
  )
  assert_true(
    report.issues().any(fn(issue) { issue.code() == "policy.rule.shadowed" }),
  )
}

///|
test "lint JSON is stable and excludes policy salt" {
  let report = lint_policy(RedactionPolicy::balanced()).render_json()
  assert_true(report.has_prefix("{\"passes\":true"))
  assert_true(!report.contains("moonredact-v1"))
}
