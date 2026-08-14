///|
test "source index maps offsets to one-based lines and columns" {
  let index = SourceIndex::new("first\nsecond\n")
  assert_eq(index.line_count(), 3)
  assert_eq(index.position(0).unwrap().render(), "1:1")
  assert_eq(index.position(6).unwrap().render(), "2:1")
  assert_eq(index.position(12).unwrap().render(), "2:7")
  assert_eq(index.position(13).unwrap().render(), "3:1")
}

///|
test "source index rejects offsets outside text" {
  let index = SourceIndex::new("abc")
  assert_eq(index.position(-1).unwrap_err().code(), "location.offset.invalid")
  assert_eq(index.position(4).unwrap_err().code(), "location.offset.invalid")
}

///|
test "locate findings preserves order across lines" {
  let source = "mail=a@example.com\nip=10.0.0.1"
  let scanned = scan(source).unwrap()
  let located = locate_findings(source, scanned).unwrap()
  assert_eq(located.length(), 2)
  assert_eq(located[0].start().render(), "1:6")
  assert_eq(located[1].start().render(), "2:4")
}

///|
test "line summary aggregates findings by their starting line" {
  let source = "a@example.com 10.0.0.1\npassword=hidden"
  let located = locate_findings(source, scan(source).unwrap()).unwrap()
  let summaries = summarize_lines(located)
  assert_eq(summaries.length(), 2)
  assert_eq(summaries[0].finding_count(), 2)
  assert_eq(summaries[1].finding_count(), 1)
}

///|
test "locate findings rejects a mismatched source" {
  let scanned = scan("a@example.com").unwrap()
  assert_eq(
    locate_findings("different", scanned).unwrap_err().code(),
    "location.source.mismatch",
  )
}
