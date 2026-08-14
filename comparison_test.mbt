///|
test "policy comparison identifies action changes without source values" {
  let before = RedactionPolicy::balanced()
  let after = RedactionPolicy::strict()
  let source = "a@example.com 10.0.0.1"
  let comparison = compare_policies(source, before, after).unwrap()
  assert_eq(comparison.finding_count(), 2)
  assert_eq(comparison.changed_count(), 2)
  let output = comparison.render_text()
  assert_true(output.contains("mask:0 -> remove"))
  assert_true(output.contains("token:ip_ -> remove"))
  assert_true(!output.contains("a@example.com"))
}

///|
test "identical policies produce no changes" {
  let policy = RedactionPolicy::balanced()
  let comparison = compare_policies("a@example.com", policy, policy).unwrap()
  assert_eq(comparison.changed_count(), 0)
  assert_eq(comparison.before_output_length(), comparison.after_output_length())
}

///|
test "token salt change is observable as replacement change" {
  let first = RedactionPolicy::new(
    default_action=Token("id_"),
    token_salt="first",
  ).unwrap()
  let second = RedactionPolicy::new(
    default_action=Token("id_"),
    token_salt="second",
  ).unwrap()
  let comparison = compare_policies("a@example.com", first, second).unwrap()
  assert_eq(comparison.changed_count(), 1)
  assert_true(comparison.changes()[0].replacement_changed())
}
