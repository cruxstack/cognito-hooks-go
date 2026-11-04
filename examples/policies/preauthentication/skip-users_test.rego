package cognito_hook_preauthentication_test

# Unit tests for skip-users.rego. Run them with:
#
#   opa test examples/policies/preauthentication/skip-users.rego examples/policies/preauthentication/skip-users_test.rego

import rego.v1

import data.cognito_hook_preauthentication as policy

sign_in(user_name, sub, client_id) := {
	"trigger": "PreAuthentication_Authentication",
	"userName": user_name,
	"callerContext": {"clientId": client_id},
	"userAttributes": {"sub": sub, "cognito:user_status": "CONFIRMED"},
	"validationData": {},
	"userNotFound": false,
	"passwordReplacedAt": null,
}

skip := {{"action": "password.skip", "reason": "end-to-end test user"}}

test_listed_sub_keeps_its_password if {
	r := policy.result with input as sign_in("8a1b2c3d-0000-4000-8000-000000000005", "8a1b2c3d-0000-4000-8000-000000000005", "1example23456789")
	r.actions == skip
}

test_listed_username_keeps_its_password if {
	r := policy.result with input as sign_in("e2e-runner", "8a1b2c3d-0000-4000-8000-000000000007", "1example23456789")
	r.actions == skip
}

test_other_users_get_the_default if {
	r := policy.result with input as sign_in("8a1b2c3d-0000-4000-8000-000000000001", "8a1b2c3d-0000-4000-8000-000000000001", "1example23456789")
	count(r.actions) == 0
}

# the app client doesn't matter, so a public client ID can't keep a password
test_the_client_does_not_matter if {
	r := policy.result with input as sign_in("8a1b2c3d-0000-4000-8000-000000000001", "8a1b2c3d-0000-4000-8000-000000000001", "9test8client7id6example")
	count(r.actions) == 0
}

test_unknown_user_gets_the_default if {
	r := policy.result with input as {"trigger": "PreAuthentication_Authentication", "userName": "mallory", "userAttributes": {}, "userNotFound": true}
	count(r.actions) == 0
}
