package cognito_hook_presignup

# Limits self sign-up to addresses in allowed_domains. Users that an
# administrator creates (AdminCreateUser) or that sign in through a federated
# identity provider for the first time are always allowed.
#
# The reason of a denial is shown to the user: Cognito returns
# "PreSignUp failed with error <reason>." to the app.

import rego.v1

allowed_domains := {"example.com", "example.org"}

result := {"actions": actions}

# signup.deny wins over signup.allow, so the allow can be unconditional and
# each rule that denies stays independent of the others
actions contains "signup.allow"

actions contains {
	"action": "signup.deny",
	"reason": "Sign-up is limited to example.com and example.org addresses.",
} if {
	input.trigger == "PreSignUp_SignUp"
	not allowed_email
}

# true for an address in an allowed domain; undefined otherwise, including
# when there's no email, so "not allowed_email" covers both
allowed_email if email_domain in allowed_domains

# the part after the last @, lowercased; undefined when there's no email
email_domain := lower(parts[count(parts) - 1]) if {
	parts := split(input.userAttributes.email, "@")
	count(parts) > 1
}
