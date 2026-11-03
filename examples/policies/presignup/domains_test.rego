package cognito_hook_presignup_test

# Unit tests for domains.rego. Run them with:
#
#   opa test examples/policies/presignup/domains.rego examples/policies/presignup/domains_test.rego

import rego.v1

import data.cognito_hook_presignup as policy

sign_up(email) := {
	"trigger": "PreSignUp_SignUp",
	"userAttributes": {"email": email},
}

denied(result) if {
	some a in result.actions
	a.action == "signup.deny"
}

test_allowed_domain_can_sign_up if {
	r := policy.result with input as sign_up("emma@example.com")
	"signup.allow" in r.actions
	not denied(r)
}

test_domain_match_ignores_case if {
	r := policy.result with input as sign_up("Emma@Example.ORG")
	not denied(r)
}

test_other_domain_is_denied_with_a_reason if {
	r := policy.result with input as sign_up("mallory@mailinator.test")
	some a in r.actions
	a.action == "signup.deny"
	a.reason != ""
}

test_lookalike_domain_is_denied if {
	denied(policy.result) with input as sign_up("mallory@example.com.mailinator.test")
}

test_missing_email_is_denied if {
	denied(policy.result) with input as {"trigger": "PreSignUp_SignUp", "userAttributes": {}}
}

test_administrators_and_federated_users_are_allowed if {
	every trigger in {"PreSignUp_AdminCreateUser", "PreSignUp_ExternalProvider"} {
		r := policy.result with input as {
			"trigger": trigger,
			"userAttributes": {"email": "noah@partner.test"},
		}
		not denied(r)
	}
}
