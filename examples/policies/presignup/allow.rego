package cognito_hook_presignup

# Allows every sign-up and sets none of Cognito's flags, as if the user pool
# had no PreSignUp trigger. Start from here and add rules.

import rego.v1

result := {"action": "allow"}
