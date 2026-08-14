///|
test "email detector accepts practical addresses and rejects malformed domains" {
  let found = detect_emails("mail alice.ops+alert@example.co.uk now")
  assert_eq(found.length(), 1)
  assert_eq(found[0].matched_text(), "alice.ops+alert@example.co.uk")
  assert_eq(found[0].span().start(), 5)
  assert_eq(detect_emails("bad a..b@example.com x@y.-com x@y.com-").length(), 0)
}

///|
test "IPv4 detector validates octets and canonical leading zeros" {
  let found = detect_ipv4_addresses("from 192.168.10.42 to 8.8.8.8")
  assert_eq(found.length(), 2)
  assert_eq(found[0].matched_text(), "192.168.10.42")
  assert_eq(detect_ipv4_addresses("999.1.1.1 01.2.3.4 1.2.3").length(), 0)
}

///|
test "payment-card detector requires a valid Luhn checksum" {
  let found = detect_payment_cards(
    "card=4111 1111 1111 1111; bad=4111 1111 1111 1112",
  )
  assert_eq(found.length(), 1)
  assert_eq(found[0].matched_text(), "4111 1111 1111 1111")
}

///|
test "credential detector captures quoted and bare assigned values" {
  let found = detect_credentials("password='hunter2' api_key: abc-123", [
    "password", "api_key",
  ])
  assert_eq(found.length(), 2)
  assert_eq(found[0].matched_text(), "hunter2")
  assert_eq(found[1].matched_text(), "abc-123")
}

///|
test "dictionary detector supports case and word boundaries" {
  let exact = DictionaryTerm::new("tenant", "ACME", whole_word=true).unwrap()
  let folded = DictionaryTerm::new("codename", "Falcon", case_sensitive=false).unwrap()
  let found = detect_dictionary("ACME ACME2 falcon", [exact, folded])
  assert_eq(found.length(), 2)
  assert_eq(found[0].sensitivity().label(), "custom:tenant")
  assert_eq(found[1].matched_text(), "falcon")
}
