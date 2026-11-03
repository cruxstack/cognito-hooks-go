// Package cognito holds what every hook shares about Amazon Cognito user pool
// trigger events.
//
// See https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-working-with-lambda-triggers.html
package cognito

import "github.com/aws/aws-lambda-go/events"

// CallerContext identifies the app client that caused the event.
type CallerContext = events.CognitoEventUserPoolsCallerContext

// Header is the part of every hook's policy input that describes the event.
// Hooks embed it, so its fields appear at the top level of the input.
type Header struct {
	// Trigger is the trigger source, such as "PreSignUp_SignUp".
	Trigger       string        `json:"trigger"`
	UserPoolID    string        `json:"userPoolId"`
	Region        string        `json:"region"`
	UserName      string        `json:"userName"`
	CallerContext CallerContext `json:"callerContext"`
}

// NewHeader returns the policy input header for an event header.
func NewHeader(h events.CognitoEventUserPoolsHeader) Header {
	return Header{
		Trigger:       h.TriggerSource,
		UserPoolID:    h.UserPoolID,
		Region:        h.Region,
		UserName:      h.UserName,
		CallerContext: h.CallerContext,
	}
}

// Map returns m, or an empty map when m is nil, so a policy sees {} instead
// of null.
func Map(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
