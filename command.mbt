///|
pub struct CommandResult {
  exit_code : Int
  output : String
} derive(Eq, @debug.Debug)

///|
pub fn CommandResult::exit_code(self : CommandResult) -> Int {
  self.exit_code
}

///|
pub fn CommandResult::output(self : CommandResult) -> String {
  self.output
}

///|
fn command_ok(output : String) -> CommandResult {
  { exit_code: 0, output }
}

///|
fn command_residual(output : String) -> CommandResult {
  { exit_code: 1, output }
}

///|
fn command_error(output : String) -> CommandResult {
  { exit_code: 2, output }
}

///|
pub let help_text =
  #|MoonRedact 0.1.0
  #|Deterministic sensitive-text detection, redaction, and auditing.
  #|
  #|USAGE:
  #|  moonredact scan              --text TEXT [--profile PROFILE] [--json]
  #|  moonredact redact            --text TEXT [--profile PROFILE] [--json]
  #|  moonredact audit             --text TEXT [--profile PROFILE] [--json]
  #|  moonredact verify            --text TEXT [--profile PROFILE] [--json]
  #|  moonredact profile-check     --profile PROFILE
  #|  moonredact profile-canonical --profile PROFILE
  #|  moonredact demo
  #|
  #|TEXT AND PROFILE: encode newlines as \n, tabs as \t, and backslashes as \\.
  #|PROFILE: key=value lines documented in docs/PROFILE_FORMAT.md.
  #|PRIVACY: scan and audit output never include matched source values.
  #|EXIT CODES: 0 success/clean, 1 residual sensitive findings, 2 invalid input.

///|
fn decode_cli_text(value : String) -> Result[String, CommandResult] {
  let output = StringBuilder::new()
  let mut escaping = false
  for char in value {
    if escaping {
      match char {
        'n' => output.write_char('\n')
        'r' => output.write_char('\r')
        't' => output.write_char('\t')
        '\\' => output.write_char('\\')
        other =>
          return Err(command_error("invalid escape: \\" + other.to_string()))
      }
      escaping = false
    } else if char == '\\' {
      escaping = true
    } else {
      output.write_char(char)
    }
  }
  if escaping {
    Err(command_error("trailing escape in text option"))
  } else {
    Ok(output.to_string())
  }
}

///|
fn optional_option(
  args : Array[String],
  name : String,
) -> Result[String?, CommandResult] {
  let mut value : String? = None
  let mut index = 1
  while index < args.length() {
    if args[index] == name {
      if value is Some(_) {
        return Err(command_error("duplicate option " + name))
      }
      if index + 1 >= args.length() {
        return Err(command_error("missing value for " + name))
      }
      value = Some(args[index + 1])
      index = index + 2
    } else {
      index = index + 1
    }
  }
  match value {
    Some(raw) =>
      match decode_cli_text(raw) {
        Ok(decoded) => Ok(Some(decoded))
        Err(error) => Err(error)
      }
    None => Ok(None)
  }
}

///|
fn required_option(
  args : Array[String],
  name : String,
) -> Result[String, CommandResult] {
  match optional_option(args, name) {
    Ok(Some(value)) => Ok(value)
    Ok(None) => Err(command_error("missing required option " + name))
    Err(error) => Err(error)
  }
}

///|
fn has_flag(args : Array[String], flag : String) -> Bool {
  args.any(fn(value) { value == flag })
}

///|
fn validate_cli_options(
  args : Array[String],
  allowed_values : Array[String],
  allowed_flags : Array[String],
) -> Result[Unit, CommandResult] {
  let mut index = 1
  while index < args.length() {
    let argument = args[index]
    if contains_exact(allowed_flags, argument) {
      index = index + 1
    } else if contains_exact(allowed_values, argument) {
      if index + 1 >= args.length() {
        return Err(command_error("missing value for " + argument))
      }
      index = index + 2
    } else {
      return Err(command_error("unknown option: " + argument))
    }
  }
  Ok(())
}

///|
fn profile_option(
  args : Array[String],
) -> Result[RedactionProfile, CommandResult] {
  match optional_option(args, "--profile") {
    Ok(Some(source)) =>
      match parse_profile(source) {
        Ok(profile) => Ok(profile)
        Err(error) => Err(command_error(error.render()))
      }
    Ok(None) => Ok(RedactionProfile::balanced())
    Err(error) => Err(error)
  }
}

///|
fn input_and_profile(
  args : Array[String],
) -> Result[(String, RedactionProfile), CommandResult] {
  match validate_cli_options(args, ["--text", "--profile"], ["--json"]) {
    Err(error) => return Err(error)
    Ok(_) => ()
  }
  let source = match required_option(args, "--text") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let profile = match profile_option(args) {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  Ok((source, profile))
}

///|
fn scan_command(args : Array[String]) -> CommandResult {
  let values = match input_and_profile(args) {
    Ok(value) => value
    Err(error) => return error
  }
  let result = match scan(values.0, config=values.1.scan_config()) {
    Ok(value) => value
    Err(error) => return command_error(error.render())
  }
  command_ok(
    if has_flag(args, "--json") {
      render_scan_json(result)
    } else {
      render_scan_text(result)
    },
  )
}

///|
fn redact_command(args : Array[String]) -> CommandResult {
  let values = match input_and_profile(args) {
    Ok(value) => value
    Err(error) => return error
  }
  let result = match
    redact(values.0, config=values.1.scan_config(), policy=values.1.policy()) {
    Ok(value) => value
    Err(error) => return command_error(error.render())
  }
  if has_flag(args, "--json") {
    command_ok(
      "{\"sanitized\":\"" +
      json_escape(result.sanitized_text()) +
      "\",\"audit\":" +
      audit(result).render_json() +
      "}",
    )
  } else {
    command_ok(result.sanitized_text())
  }
}

///|
fn audit_command(args : Array[String]) -> CommandResult {
  let values = match input_and_profile(args) {
    Ok(value) => value
    Err(error) => return error
  }
  let result = match
    redact(values.0, config=values.1.scan_config(), policy=values.1.policy()) {
    Ok(value) => value
    Err(error) => return command_error(error.render())
  }
  let report = audit(result)
  command_ok(
    if has_flag(args, "--json") {
      report.render_json()
    } else {
      report.render_text().trim().to_owned()
    },
  )
}

///|
fn verify_command(args : Array[String]) -> CommandResult {
  let values = match input_and_profile(args) {
    Ok(value) => value
    Err(error) => return error
  }
  let result = match
    redact(values.0, config=values.1.scan_config(), policy=values.1.policy()) {
    Ok(value) => value
    Err(error) => return command_error(error.render())
  }
  let residual = match verify_sanitized(result, config=values.1.scan_config()) {
    Ok(value) => value
    Err(error) => return command_error(error.render())
  }
  let output = if has_flag(args, "--json") {
    render_residual_json(residual)
  } else {
    render_residual_text(residual)
  }
  if residual.is_clean() {
    command_ok(output)
  } else {
    command_residual(output)
  }
}

///|
fn profile_command(args : Array[String], canonical : Bool) -> CommandResult {
  match validate_cli_options(args, ["--profile"], []) {
    Err(error) => return error
    Ok(_) => ()
  }
  let source = match required_option(args, "--profile") {
    Ok(value) => value
    Err(error) => return error
  }
  match parse_profile(source) {
    Ok(profile) =>
      command_ok(
        if canonical {
          profile.canonical().trim().to_owned()
        } else {
          "profile valid"
        },
      )
    Err(error) => command_error(error.render())
  }
}

///|
pub fn demo_text() -> String {
  "contact=alice@example.com source=10.20.30.40 password='open-sesame' card=4111 1111 1111 1111"
}

///|
fn demo_command() -> CommandResult {
  let result = redact(demo_text()).unwrap()
  command_ok(
    "SANITIZED\n" +
    result.sanitized_text() +
    "\n\n" +
    audit(result).render_text().trim().to_owned(),
  )
}

///|
pub fn execute(args : Array[String]) -> CommandResult {
  if args.is_empty() {
    return command_ok(help_text)
  }
  match args[0] {
    "help" | "--help" | "-h" => command_ok(help_text)
    "scan" => scan_command(args)
    "redact" => redact_command(args)
    "audit" => audit_command(args)
    "verify" => verify_command(args)
    "profile-check" => profile_command(args, false)
    "profile-canonical" => profile_command(args, true)
    "demo" => demo_command()
    other => command_error("unknown command: " + other + "\n\n" + help_text)
  }
}
