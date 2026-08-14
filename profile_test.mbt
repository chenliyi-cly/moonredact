///|
test "profile parser builds detectors, dictionary, allowlist, and rules" {
  let profile = parse_profile(
    "# deployment profile\nmax-input=4096\nallow=127.0.0.1\ndictionary=tenant|ACME|word|700\ncredential-key=passphrase\ndefault=remove\nsalt=test-salt\nrule=payment-card|mask:4|900\nrule=ipv4|token:net_|800",
  ).unwrap()
  assert_eq(profile.scan_config().max_input_chars(), 4096)
  assert_eq(profile.scan_config().allowlist(), ["127.0.0.1"])
  assert_eq(profile.scan_config().dictionary().length(), 1)
  assert_eq(profile.policy().rules().length(), 2)
  assert_eq(profile.policy().action_for(PaymentCard).label(), "mask:4")
}

///|
test "profile parser supports detector selection" {
  let profile = parse_profile("detectors=email\ndefault=mask:0").unwrap()
  let result = redact(
    "a@example.com 10.0.0.1",
    config=profile.scan_config(),
    policy=profile.policy(),
  ).unwrap()
  assert_eq(result.decisions().length(), 1)
}

///|
test "profile parser reports stable malformed-line diagnostics" {
  assert_eq(
    parse_profile("unknown=yes").unwrap_err().code(),
    "profile.key.unknown",
  )
  assert_eq(
    parse_profile("rule=email|remove").unwrap_err().code(),
    "profile.rule.fields",
  )
  assert_eq(
    parse_profile("default=mask:999").unwrap_err().code(),
    "policy.mask.invalid",
  )
  assert_eq(
    parse_profile("detectors=email,magic").unwrap_err().code(),
    "profile.detector.unknown",
  )
}

///|
test "canonical profile can be parsed again" {
  let first = parse_profile(
    "detectors=email,credential\nallow=localhost\ndictionary=team|Alpha|fold-word|80\ndefault=token:id_\nrule=credential|remove|900",
  ).unwrap()
  let second = parse_profile(first.canonical()).unwrap()
  assert_eq(second.scan_config().allowlist(), ["localhost"])
  assert_eq(second.policy().action_for(Credential).label(), "remove")
  let scanned = scan("a@example.com 10.0.0.1", config=second.scan_config()).unwrap()
  assert_eq(scanned.findings().length(), 1)
}

///|
test "action parser rejects malformed actions" {
  assert_eq(
    parse_action("mask:x").unwrap_err().code(),
    "profile.integer.invalid",
  )
  assert_eq(
    parse_action("token:").unwrap_err().code(),
    "policy.token-prefix.invalid",
  )
  assert_eq(
    parse_action("encrypt").unwrap_err().code(),
    "profile.action.invalid",
  )
}

///|
test "canonical profile preserves an intentionally empty built-in detector set" {
  let config = ScanConfig::default()
    .with_email(false)
    .with_ipv4(false)
    .with_payment_card(false)
    .with_credential(false)
  let profile = RedactionProfile::new(config, RedactionPolicy::strict())
  let parsed = parse_profile(profile.canonical()).unwrap()
  assert_eq(
    scan("a@example.com 10.0.0.1", config=parsed.scan_config())
    .unwrap()
    .findings()
    .length(),
    0,
  )
}
