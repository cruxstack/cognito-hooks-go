package cognito_hook_postconfirmation_test

# Unit tests for skip-clients.rego. Run them with:
#
#   opa test examples/policies/postconfirmation/skip-clients.rego examples/policies/postconfirmation/skip-clients_test.rego

import rego.v1

import data.cognito_hook_postconfirmation as policy

confirmed(client_id) := {
	"trigger": "PostConfirmation_ConfirmSignUp",
	"callerContext": {"clientId": client_id},
}

test_test_client_is_skipped if {
	r := policy.result with input as confirmed("9test8client7id6example")
	r.action == "skip"
	r.reason == "end-to-end test client"
}

test_other_clients_are_scrambled if {
	policy.result.action == "scramble" with input as confirmed("1example23456789")
}

test_missing_client_is_scrambled if {
	policy.result.action == "scramble" with input as {"trigger": "PostConfirmation_ConfirmForgotPassword"}
}
