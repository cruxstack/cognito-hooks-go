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

test_test_client_keeps_its_password if {
	r := policy.result with input as confirmed("9test8client7id6example")
	r.actions == {{"action": "password.skip", "reason": "end-to-end test client"}}
}

test_other_clients_get_the_default if {
	r := policy.result with input as confirmed("1example23456789")
	count(r.actions) == 0
}

test_missing_client_gets_the_default if {
	r := policy.result with input as {"trigger": "PostConfirmation_ConfirmForgotPassword"}
	count(r.actions) == 0
}
