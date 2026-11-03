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

test_valid_address_is_allowed if {
	policy.result.action == "allow" with input as sign_up({"valid": true, "verdict": "Valid", "disposable": false})
}

test_risky_address_is_allowed if {
	policy.result.action == "allow" with input as sign_up({"valid": true, "verdict": "Risky", "disposable": false})
}

test_undeliverable_address_is_denied if {
	r := policy.result with input as sign_up({"valid": false, "verdict": "Invalid", "disposable": true})
	r.action == "deny"
	r.reason == "Enter an email address that can receive email."
}

test_disposable_address_is_denied if {
	r := policy.result with input as sign_up({"valid": true, "verdict": "Risky", "disposable": true})
	r.action == "deny"
	r.reason == "Disposable email addresses can't be used to sign up."
}

test_unverified_sign_up_is_allowed if {
	policy.result.action == "allow" with input as {"trigger": "PreSignUp_SignUp", "userAttributes": {"email": "user@example.com"}}
}
