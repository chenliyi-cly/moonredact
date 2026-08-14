///|
pub(all) enum RedactionAction {
  Keep
  Mask(Int)
  Remove
  Token(String)
} derive(Eq, @debug.Debug)

///|
pub fn RedactionAction::label(self : RedactionAction) -> String {
  match self {
    Keep => "keep"
    Mask(visible) => "mask:" + visible.to_string()
    Remove => "remove"
    Token(prefix) => "token:" + prefix
  }
}

///|
fn validate_action(
  action : RedactionAction,
  location : String,
) -> Result[Unit, Diagnostic] {
  match action {
    Keep | Remove => Ok(())
    Mask(visible) =>
      if visible < 0 || visible > 64 {
        Err(
          Diagnostic::new(
            "policy.mask.invalid",
            location,
            "mask visibility is outside the supported range",
            "0 through 64",
            visible.to_string(),
          ),
        )
      } else {
        Ok(())
      }
    Token(prefix) => {
      if prefix.is_empty() || prefix.length() > 32 {
        return Err(
          Diagnostic::new(
            "policy.token-prefix.invalid",
            location,
            "token prefix length is invalid",
            "1 through 32 characters",
            prefix.length().to_string(),
          ),
        )
      }
      for char in prefix {
        if !is_ascii_alphanumeric(char) && char != '_' && char != '-' {
          return Err(
            Diagnostic::new(
              "policy.token-prefix.character",
              location,
              "token prefix contains an unsupported character",
              "ASCII letter, digit, underscore, or hyphen",
              char.to_string(),
            ),
          )
        }
      }
      Ok(())
    }
  }
}

///|
pub struct PolicyRule {
  selector : String
  action : RedactionAction
  priority : Int
} derive(Eq, @debug.Debug)

///|
fn valid_selector(value : String) -> Bool {
  value == "*" ||
  value == "email" ||
  value == "ipv4" ||
  value == "payment-card" ||
  value == "credential" ||
  value == "custom:*" ||
  (value.has_prefix("custom:") && value.length() > 7)
}

///|
pub fn PolicyRule::new(
  selector : String,
  action : RedactionAction,
  priority? : Int = 100,
) -> Result[PolicyRule, Diagnostic] {
  let normalized = ascii_lower_text(selector.trim().to_owned())
  if !valid_selector(normalized) {
    return Err(
      Diagnostic::new(
        "policy.selector.invalid", "policy.selector", "policy selector is unsupported",
        "*, built-in class, custom:*, or custom:name", normalized,
      ),
    )
  }
  if priority < 0 || priority > 1000 {
    return Err(
      Diagnostic::new(
        "policy.priority.invalid",
        "policy.priority",
        "policy priority is outside the supported range",
        "0 through 1000",
        priority.to_string(),
      ),
    )
  }
  match validate_action(action, "policy.action") {
    Err(error) => return Err(error)
    Ok(_) => ()
  }
  Ok({ selector: normalized, action, priority })
}

///|
pub fn PolicyRule::selector(self : PolicyRule) -> String {
  self.selector
}

///|
pub fn PolicyRule::action(self : PolicyRule) -> RedactionAction {
  self.action
}

///|
pub fn PolicyRule::priority(self : PolicyRule) -> Int {
  self.priority
}

///|
pub struct RedactionPolicy {
  default_action : RedactionAction
  rules : Array[PolicyRule]
  token_salt : String
} derive(Eq, @debug.Debug)

///|
pub fn RedactionPolicy::new(
  default_action? : RedactionAction = Mask(0),
  rules? : Array[PolicyRule] = [],
  token_salt? : String = "moonredact-v1",
) -> Result[RedactionPolicy, Diagnostic] {
  match validate_action(default_action, "policy.default") {
    Err(error) => return Err(error)
    Ok(_) => ()
  }
  if token_salt.is_empty() || token_salt.length() > 128 {
    return Err(
      Diagnostic::new(
        "policy.token-salt.invalid",
        "policy.token-salt",
        "token salt length is invalid",
        "1 through 128 characters",
        token_salt.length().to_string(),
      ),
    )
  }
  Ok({ default_action, rules: rules.copy(), token_salt })
}

///|
pub fn RedactionPolicy::balanced() -> RedactionPolicy {
  RedactionPolicy::new(default_action=Mask(0), rules=[
    PolicyRule::new("email", Mask(0), priority=200).unwrap(),
    PolicyRule::new("ipv4", Token("ip_"), priority=200).unwrap(),
    PolicyRule::new("payment-card", Mask(4), priority=300).unwrap(),
    PolicyRule::new("credential", Remove, priority=400).unwrap(),
    PolicyRule::new("custom:*", Mask(0), priority=100).unwrap(),
  ]).unwrap()
}

///|
pub fn RedactionPolicy::strict() -> RedactionPolicy {
  RedactionPolicy::new(default_action=Remove).unwrap()
}

///|
/// Policy that reports findings without altering matched text.
pub fn RedactionPolicy::passthrough() -> RedactionPolicy {
  RedactionPolicy::new(default_action=Keep).unwrap()
}

///|
fn selector_matches(selector : String, sensitivity : Sensitivity) -> Bool {
  selector == "*" ||
  selector == sensitivity.label() ||
  (selector == "custom:*" && sensitivity is Custom(_))
}

///|
pub fn RedactionPolicy::action_for(
  self : RedactionPolicy,
  sensitivity : Sensitivity,
) -> RedactionAction {
  let mut selected = self.default_action
  let mut selected_priority = -1
  for rule in self.rules {
    if selector_matches(rule.selector, sensitivity) &&
      rule.priority > selected_priority {
      selected = rule.action
      selected_priority = rule.priority
    }
  }
  selected
}

///|
pub fn RedactionPolicy::rules(self : RedactionPolicy) -> Array[PolicyRule] {
  self.rules.copy()
}

///|
pub fn RedactionPolicy::default_action(
  self : RedactionPolicy,
) -> RedactionAction {
  self.default_action
}
