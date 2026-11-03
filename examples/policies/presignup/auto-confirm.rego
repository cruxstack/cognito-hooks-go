package cognito_hook_presignup

# Confirms sign-ups from the end-to-end test app client with addresses at the
# test domain, and marks their email verified, so automated tests don't have
# to read a confirmation email. Everyone else confirms their address as usual.
#
# Only auto-verify addresses you control: a verified address can receive
# password resets and sign-in codes.

import rego.v1

e2e_client_id := "9test8client7id6example"

e2e_domain := "example.com"

default result := {"action": "allow"}

result := {
	"action": "allow",
	"response": {"autoConfirmUser": true, "autoVerifyEmail": true},
} if {
	input.trigger == "PreSignUp_SignUp"
	input.callerContext.clientId == e2e_client_id
	endswith(lower(input.userAttributes.email), concat("", ["@", e2e_domain]))
}
