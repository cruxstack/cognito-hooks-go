package cognito_hook_postconfirmation

# Keeps the passwords of users that sign up through the end-to-end test app
# client, so automated tests can sign in with a password. Every other native
# user's password is scrambled. Federated users are always skipped, before the
# policy runs.

import rego.v1

e2e_client_ids := {"9test8client7id6example"}

default result := {"action": "scramble"}

result := {"action": "skip", "reason": "end-to-end test client"} if {
	input.callerContext.clientId in e2e_client_ids
}
