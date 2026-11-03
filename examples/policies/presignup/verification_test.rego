package cognito_hook_presignup_test

# Unit tests for verification.rego. Run them with:
#
#   opa test examples/policies/presignup/verification.rego examples/policies/presignup/verification_test.rego

import rego.v1

import data.cognito_hook_presignup as policy

sign_up(verification) := {
	"trigger": "PreSignUp_SignUp",
	"userAttributes": {"email": "user@example.com"},
	"emailVerification": verification,
}

# the reasons of the policy's denials
denials(result) := {a.reason | some a in result.actions; a.action == "signup.deny"}

test_valid_address_is_allowed if {
	r := policy.result with input as sign_up({"valid": true, "verdict": "Valid", "disposable": false})
	"signup.allow" in r.actions
	count(denials(r)) == 0
}

test_risky_address_is_allowed if {
	r := policy.result with input as sign_up({"valid": true, "verdict": "Risky", "disposable": false})
	count(denials(r)) == 0
}

test_undeliverable_address_is_denied if {
	r := policy.result with input as sign_up({"valid": false, "verdict": "Invalid", "disposable": true})
	denials(r) == {"Enter an email address that can receive email."}
}

test_disposable_address_is_denied if {
	r := policy.result with input as sign_up({"valid": true, "verdict": "Risky", "disposable": true})
	denials(r) == {"Disposable email addresses can't be used to sign up."}
}

test_unverified_sign_up_is_allowed if {
	r := policy.result with input as {"trigger": "PreSignUp_SignUp", "userAttributes": {"email": "user@example.com"}}
	count(denials(r)) == 0
}
