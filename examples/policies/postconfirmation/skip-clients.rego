package cognito_hook_postconfirmation

# Keeps the passwords of users that sign up through the end-to-end test app
# client (password.skip), so automated tests can sign in with a password.
# Every other native user's password is replaced: password.replace is the
# default when the policy returns no password action.

import rego.v1

e2e_client_ids := {"9test8client7id6example"}

result := {"actions": actions}

actions contains {"action": "password.skip", "reason": "end-to-end test client"} if {
	input.callerContext.clientId in e2e_client_ids
}
