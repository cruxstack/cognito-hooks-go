package cognito_hook_presignup

# Denies sign-ups with undeliverable or disposable addresses, using the
# result of email verification (APP_EMAIL_VERIFICATION_ENABLED=true).
#
# input.emailVerification is missing when verification is off for the
# trigger or SendGrid couldn't be reached. Comparing with "== true" or
# "== false" (instead of using "not") lets those sign-ups through, so a
# SendGrid outage doesn't block sign-ups.

import rego.v1

result := {"actions": actions}

actions contains "signup.allow"

actions contains deny("Enter an email address that can receive email.") if {
	input.emailVerification.valid == false
}

actions contains deny("Disposable email addresses can't be used to sign up.") if {
	input.emailVerification.valid == true
	input.emailVerification.disposable == true
}

deny(reason) := {"action": "signup.deny", "reason": reason}
