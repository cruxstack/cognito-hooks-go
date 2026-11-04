package cognito_hook_preauthentication

# Keeps the passwords of a list of users (password.skip), such as the
# accounts an end-to-end test suite signs in to with a password. Every other
# native, confirmed user's password is replaced at sign-in unless the hooks
# have replaced it since the cutoff: password.replace is the default when the
# policy returns no password action.
#
# List users by sub or username. Don't skip by app client ID
# (input.callerContext.clientId) or by validationData: a client without a
# secret has a public ID, and the app chooses its own ClientMetadata, so
# anyone could sign in through that client and keep a leaked password
# working.

import rego.v1

# a user's sub never changes, so prefer it to the username
e2e_subs := {"8a1b2c3d-0000-4000-8000-000000000005"}

# usernames are matched exactly as Cognito sends them in userName
e2e_usernames := {"e2e-runner"}

result := {"actions": actions}

actions contains {"action": "password.skip", "reason": "end-to-end test user"} if {
	input.userAttributes.sub in e2e_subs
}

actions contains {"action": "password.skip", "reason": "end-to-end test user"} if {
	input.userName in e2e_usernames
}
