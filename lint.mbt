///|
pub enum IssueSeverity {
  Info
  Warning
  Error
} derive(Eq, @debug.Debug)

///|
pub fn IssueSeverity::label(self : IssueSeverity) -> String {
  match self {
    Info => "info"
    Warning => "warning"
    Error => "error"
  }
}

///|
pub struct PolicyIssue {
  severity : IssueSeverity
  code : String
  selector : String
  message : String
} derive(Eq, @debug.Debug)

///|
fn make_policy_issue(
  severity : IssueSeverity,
  code : String,
  selector : String,
  message : String,
) -> PolicyIssue {
  { severity, code, selector, message }
}

///|
pub fn PolicyIssue::severity(self : PolicyIssue) -> IssueSeverity {
  self.severity
}

///|
pub fn PolicyIssue::code(self : PolicyIssue) -> String {
  self.code
}

///|
pub fn PolicyIssue::selector(self : PolicyIssue) -> String {
  self.selector
}

///|
pub fn PolicyIssue::message(self : PolicyIssue) -> String {
  self.message
}

///|
pub struct ClassPosture {
  sensitivity : String
  action : RedactionAction
  risk_score : Int
  explicit_rule : Bool
} derive(Eq, @debug.Debug)

///|
pub fn ClassPosture::sensitivity(self : ClassPosture) -> String {
  self.sensitivity
}

///|
pub fn ClassPosture::action(self : ClassPosture) -> RedactionAction {
  self.action
}

///|
pub fn ClassPosture::risk_score(self : ClassPosture) -> Int {
  self.risk_score
}

///|
pub fn ClassPosture::has_explicit_rule(self : ClassPosture) -> Bool {
  self.explicit_rule
}

///|
fn action_risk(action : RedactionAction) -> Int {
  match action {
    Keep => 100
    Mask(visible) => if visible == 0 { 20 } else { 35 }
    Token(_) => 15
    Remove => 0
  }
}

///|
fn rule_matches(rule : PolicyRule, sensitivity : Sensitivity) -> Bool {
  selector_matches(rule.selector, sensitivity)
}

///|
fn selected_rule_index(
  policy : RedactionPolicy,
  sensitivity : Sensitivity,
) -> Int? {
  let mut selected = -1
  let mut priority = -1
  for index, rule in policy.rules {
    if rule_matches(rule, sensitivity) && rule.priority > priority {
      selected = index
      priority = rule.priority
    }
  }
  if selected < 0 {
    None
  } else {
    Some(selected)
  }
}

///|
fn representative_for_selector(selector : String) -> Sensitivity {
  match selector {
    "email" => Email
    "ipv4" => IPv4
    "payment-card" => PaymentCard
    "credential" => Credential
    "custom:*" => Custom("representative")
    _ =>
      if selector.has_prefix("custom:") {
        Custom(selector[7:].to_owned())
      } else {
        Email
      }
  }
}

///|
fn rule_selected_anywhere(policy : RedactionPolicy, rule_index : Int) -> Bool {
  let rule = policy.rules[rule_index]
  let samples = [
    Email,
    IPv4,
    PaymentCard,
    Credential,
    representative_for_selector(rule.selector),
  ]
  for sensitivity in samples {
    if rule_matches(rule, sensitivity) {
      match selected_rule_index(policy, sensitivity) {
        Some(selected) => if selected == rule_index { return true }
        None => ()
      }
    }
  }
  false
}

///|
fn action_is_token(action : RedactionAction) -> Bool {
  action is Token(_)
}

///|
fn policy_uses_token(policy : RedactionPolicy) -> Bool {
  if action_is_token(policy.default_action) {
    return true
  }
  for rule in policy.rules {
    if action_is_token(rule.action) {
      return true
    }
  }
  false
}

///|
fn policy_has_selector(policy : RedactionPolicy, selector : String) -> Bool {
  for rule in policy.rules {
    if rule.selector == selector {
      return true
    }
  }
  false
}

///|
fn duplicate_rule_issues(
  policy : RedactionPolicy,
  issues : Array[PolicyIssue],
) -> Unit {
  for index, rule in policy.rules {
    for earlier = 0; earlier < index; earlier = earlier + 1 {
      let previous = policy.rules[earlier]
      if rule.selector == previous.selector &&
        rule.priority == previous.priority {
        if rule.action == previous.action {
          issues.push(
            make_policy_issue(
              Warning,
              "policy.rule.redundant",
              rule.selector,
              "rule repeats an earlier selector, priority, and action",
            ),
          )
        } else {
          issues.push(
            make_policy_issue(
              Error,
              "policy.rule.ambiguous",
              rule.selector,
              "rule conflicts with an earlier action at the same priority; the earlier rule wins",
            ),
          )
        }
      }
    }
  }
}

///|
fn shadowed_rule_issues(
  policy : RedactionPolicy,
  issues : Array[PolicyIssue],
) -> Unit {
  for index, rule in policy.rules {
    if !rule_selected_anywhere(policy, index) {
      issues.push(
        make_policy_issue(
          Warning,
          "policy.rule.shadowed",
          rule.selector,
          "rule is never selected for its sensitivity class",
        ),
      )
    }
  }
}

///|
fn exposure_issues(
  policy : RedactionPolicy,
  issues : Array[PolicyIssue],
) -> Unit {
  if policy.default_action is Keep {
    issues.push(
      make_policy_issue(
        Error,
        "policy.default.keep",
        "*",
        "default keep leaves unmatched sensitivity classes unchanged",
      ),
    )
  }
  for rule in policy.rules {
    if rule.action is Keep {
      issues.push(
        make_policy_issue(
          Warning,
          "policy.rule.keep",
          rule.selector,
          "selected findings for this rule remain in output",
        ),
      )
    }
  }
  let credential_action = policy.action_for(Credential)
  if credential_action is Keep || credential_action is Mask(_) {
    issues.push(
      make_policy_issue(
        Error,
        "policy.credential.weak",
        "credential",
        "credentials should normally be removed or irreversibly tokenized",
      ),
    )
  } else if !policy_has_selector(policy, "credential") &&
    policy.default_action is Remove {
    issues.push(
      make_policy_issue(
        Info,
        "policy.credential.inherited",
        "credential",
        "credential protection is inherited from the default action",
      ),
    )
  }
  if policy.action_for(PaymentCard) is Keep {
    issues.push(
      make_policy_issue(
        Error,
        "policy.payment-card.keep",
        "payment-card",
        "payment-card findings remain unchanged",
      ),
    )
  }
}

///|
fn token_issues(policy : RedactionPolicy, issues : Array[PolicyIssue]) -> Unit {
  if policy_uses_token(policy) && policy.token_salt == "moonredact-v1" {
    issues.push(
      make_policy_issue(
        Warning,
        "policy.token-salt.default",
        "token",
        "token actions use the documented default salt; set a deployment-specific non-secret salt for separate correlation domains",
      ),
    )
  }
  for rule in policy.rules {
    match rule.action {
      Token(prefix) =>
        if prefix.length() < 2 {
          issues.push(
            make_policy_issue(
              Info,
              "policy.token-prefix.short",
              rule.selector,
              "a longer token prefix makes sanitized output easier to classify",
            ),
          )
        }
      _ => ()
    }
  }
}

///|
fn policy_postures(policy : RedactionPolicy) -> Array[ClassPosture] {
  let sensitivities = [
    Email,
    IPv4,
    PaymentCard,
    Credential,
    Custom("representative"),
  ]
  let values : Array[ClassPosture] = []
  for sensitivity in sensitivities {
    let action = policy.action_for(sensitivity)
    values.push({
      sensitivity: if sensitivity is Custom(_) {
        "custom:*"
      } else {
        sensitivity.label()
      },
      action,
      risk_score: action_risk(action),
      explicit_rule: selected_rule_index(policy, sensitivity) is Some(_),
    })
  }
  values
}

///|
pub struct PolicyLintReport {
  issues : Array[PolicyIssue]
  postures : Array[ClassPosture]
  errors : Int
  warnings : Int
  information : Int
  total_risk : Int
} derive(Eq, @debug.Debug)

///|
pub fn lint_policy(policy : RedactionPolicy) -> PolicyLintReport {
  let issues : Array[PolicyIssue] = []
  duplicate_rule_issues(policy, issues)
  shadowed_rule_issues(policy, issues)
  exposure_issues(policy, issues)
  token_issues(policy, issues)
  let postures = policy_postures(policy)
  let mut errors = 0
  let mut warnings = 0
  let mut information = 0
  let mut risk = 0
  for issue in issues {
    match issue.severity {
      Error => errors = errors + 1
      Warning => warnings = warnings + 1
      Info => information = information + 1
    }
  }
  for posture in postures {
    risk = risk + posture.risk_score
  }
  { issues, postures, errors, warnings, information, total_risk: risk }
}

///|
pub fn PolicyLintReport::issues(self : PolicyLintReport) -> Array[PolicyIssue] {
  self.issues.copy()
}

///|
pub fn PolicyLintReport::postures(
  self : PolicyLintReport,
) -> Array[ClassPosture] {
  self.postures.copy()
}

///|
pub fn PolicyLintReport::error_count(self : PolicyLintReport) -> Int {
  self.errors
}

///|
pub fn PolicyLintReport::warning_count(self : PolicyLintReport) -> Int {
  self.warnings
}

///|
pub fn PolicyLintReport::info_count(self : PolicyLintReport) -> Int {
  self.information
}

///|
pub fn PolicyLintReport::risk_score(self : PolicyLintReport) -> Int {
  self.total_risk
}

///|
pub fn PolicyLintReport::passes(self : PolicyLintReport) -> Bool {
  self.errors == 0
}

///|
pub fn PolicyLintReport::render_text(self : PolicyLintReport) -> String {
  let output = StringBuilder::new()
  output.write_string("MoonRedact policy lint\n")
  output.write_string("errors: " + self.errors.to_string() + "\n")
  output.write_string("warnings: " + self.warnings.to_string() + "\n")
  output.write_string("info: " + self.information.to_string() + "\n")
  output.write_string("risk-score: " + self.total_risk.to_string())
  for posture in self.postures {
    output.write_string(
      "\nposture " +
      posture.sensitivity +
      " action=" +
      posture.action.label() +
      " risk=" +
      posture.risk_score.to_string() +
      " explicit=" +
      posture.explicit_rule.to_string(),
    )
  }
  for issue in self.issues {
    output.write_string(
      "\n" +
      issue.severity.label() +
      " " +
      issue.code +
      " selector=" +
      issue.selector +
      ": " +
      issue.message,
    )
  }
  output.to_string()
}

///|
pub fn PolicyLintReport::render_json(self : PolicyLintReport) -> String {
  let output = StringBuilder::new()
  output.write_string(
    "{\"passes\":" +
    self.passes().to_string() +
    ",\"errors\":" +
    self.errors.to_string() +
    ",\"warnings\":" +
    self.warnings.to_string() +
    ",\"info\":" +
    self.information.to_string() +
    ",\"risk_score\":" +
    self.total_risk.to_string() +
    ",\"issues\":[",
  )
  for index, issue in self.issues {
    if index > 0 {
      output.write_char(',')
    }
    output.write_string(
      "{\"severity\":\"" +
      issue.severity.label() +
      "\",\"code\":\"" +
      json_escape(issue.code) +
      "\",\"selector\":\"" +
      json_escape(issue.selector) +
      "\"}",
    )
  }
  output.write_string("]}")
  output.to_string()
}
