///|
test "CLI help and unknown commands have stable status" {
  assert_eq(execute([]).exit_code(), 0)
  assert_true(execute([]).output().contains("MoonRedact 0.1.0"))
  assert_eq(execute(["unknown"]).exit_code(), 2)
}

///|
test "scan CLI does not disclose matched values" {
  let result = execute(["scan", "--text", "password=super-secret a@example.com"])
  assert_eq(result.exit_code(), 0)
  assert_true(result.output().contains("credential"))
  assert_true(!result.output().contains("super-secret"))
  assert_true(!result.output().contains("a@example.com"))
}

///|
test "redact and audit CLI use decoded profile text" {
  let profile = "default=remove\\nrule=email|keep|900"
  let redacted = execute([
    "redact", "--text", "a@example.com 10.0.0.1", "--profile", profile,
  ])
  assert_eq(redacted.output(), "a@example.com ")
  let audited = execute(["audit", "--text", "a@example.com", "--json"])
  assert_true(audited.output().has_prefix("{\"input_chars\":13"))
}

///|
test "verify CLI distinguishes clean and residual output" {
  let clean = execute(["verify", "--text", "a@example.com"])
  assert_eq(clean.exit_code(), 0)
  let residual = execute([
    "verify", "--text", "a@example.com", "--profile", "default=keep",
  ])
  assert_eq(residual.exit_code(), 1)
  assert_true(residual.output().contains("RESIDUAL"))
}

///|
test "CLI validates required duplicate and unknown options" {
  assert_eq(execute(["scan"]).exit_code(), 2)
  assert_eq(execute(["scan", "--text", "a", "--text", "b"]).exit_code(), 2)
  assert_eq(execute(["scan", "--text", "a", "--wat"]).exit_code(), 2)
  assert_eq(
    execute(["profile-check", "--profile", "default=remove"]).output(),
    "profile valid",
  )
}

///|
test "demo exercises every built-in detector class" {
  let result = execute(["demo"])
  assert_eq(result.exit_code(), 0)
  assert_true(result.output().contains("credential: 1"))
  assert_true(result.output().contains("payment-card: 1"))
  assert_true(result.output().contains("email: 1"))
  assert_true(result.output().contains("ipv4: 1"))
}

///|
test "policy lint CLI returns one for unsafe policy" {
  let exposed = execute(["policy-lint", "--profile", "default=keep"])
  assert_eq(exposed.exit_code(), 1)
  assert_true(exposed.output().contains("policy.default.keep"))
  let strict = execute(["policy-lint", "--profile", "default=remove", "--json"])
  assert_eq(strict.exit_code(), 0)
  assert_true(strict.output().has_prefix("{\"passes\":true"))
}
