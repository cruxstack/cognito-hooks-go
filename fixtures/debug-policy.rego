package cognito_hook_presignup

import rego.v1

# choose deny when email verification exists and is invalid
result := deny_result if {
  input.emailVerification != null
  input.emailVerification.valid == false
}

# otherwise allow
result := allow_result if {
  not deny_result
}

# constant allow result
allow_result := {
 "action": "allow",
 "response": {}
}

# deny result only when invalid email
deny_result := {
  "action": "deny",
  "reason": "invalid email address"
} if {
  input.emailVerification != null
  input.emailVerification.valid == false
}

