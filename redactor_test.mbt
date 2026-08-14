///|
test "balanced policy masks cards, removes credentials, and tokens IPs" {
  let result = redact("ip=10.0.0.8 password=hunter2 card=4111 1111 1111 1111").unwrap()
  assert_eq(
    result.sanitized_text(),
    "ip=ip_elyc5k00 password= card=**** **** **** 1111",
  )
  assert_eq(result.decisions().length(), 3)
}

///|
test "email masking preserves punctuation shape" {
  let result = redact("contact alice@example.com").unwrap()
  assert_eq(result.sanitized_text(), "contact *****@*******.***")
}

///|
test "strict policy removes every accepted finding" {
  let result = redact(
    "a@example.com from 10.0.0.1",
    policy=RedactionPolicy::strict(),
  ).unwrap()
  assert_eq(result.sanitized_text(), " from ")
}

///|
test "custom policy can keep a selected class" {
  let rule = PolicyRule::new("email", Keep).unwrap()
  let policy = RedactionPolicy::new(default_action=Remove, rules=[rule]).unwrap()
  let result = redact("a@example.com 10.0.0.1", policy~).unwrap()
  assert_eq(result.sanitized_text(), "a@example.com ")
}

///|
test "token output is deterministic and salt-sensitive" {
  let first = RedactionPolicy::new(default_action=Token("x_"), token_salt="one").unwrap()
  let second = RedactionPolicy::new(
    default_action=Token("x_"),
    token_salt="two",
  ).unwrap()
  let a = redact("a@example.com", policy=first).unwrap().sanitized_text()
  let b = redact("a@example.com", policy=first).unwrap().sanitized_text()
  let c = redact("a@example.com", policy=second).unwrap().sanitized_text()
  assert_eq(a, b)
  assert_true(a != c)
}
