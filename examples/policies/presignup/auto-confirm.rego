package cognito_hook_presignup

# Confirms sign-ups from the end-to-end test app client with addresses at the
# test domain (user.confirm), so automated tests don't have to read a
# confirmation email. Everyone else confirms their address as usual.
#
# An app client ID isn't a secret. Give the test app client a client secret,
# so only your test suite can sign up through it; otherwise anyone who knows
# the ID can create confirmed accounts at the test domain.
#
# This doesn't return email.verify. Auto-verifying an address skips the
# proof that the user owns it, and when email is a sign-in alias, Cognito
# moves an existing user's alias to the new user.

import rego.v1

e2e_client_id := "9test8client7id6example"

e2e_domain := "example.com"

result := {"actions": actions}

actions contains "signup.allow"

actions contains "user.confirm" if {
	input.trigger == "PreSignUp_SignUp"
	input.callerContext.clientId == e2e_client_id
	endswith(lower(input.userAttributes.email), concat("", ["@", e2e_domain]))
}
