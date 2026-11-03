package handler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cruxstack/cognito-hooks-go/internal/postconfirmation"
	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
)

type hookFunc[E any] func(context.Context, *E) error

func (f hookFunc[E]) Handle(ctx context.Context, e *E) error { return f(ctx, e) }

func raw(trigger string) json.RawMessage {
	return json.RawMessage(`{"version":"1","triggerSource":"` + trigger + `","region":"us-east-1","userPoolId":"us-east-1_EXAMPLE",` +
		`"userName":"user-1","callerContext":{"clientId":"web"},"request":{"userAttributes":{"email":"a@example.com"}},"response":{}}`)
}

func TestHandle_RoutesByTrigger(t *testing.T) {
	var got []string
	h := &Handler{
		PreSignUp: hookFunc[presignup.Event](func(_ context.Context, e *presignup.Event) error {
			got = append(got, "presignup:"+e.Request.UserAttributes["email"])
			e.Response.AutoConfirmUser = true
			return nil
		}),
		PostConfirmation: hookFunc[postconfirmation.Event](func(_ context.Context, e *postconfirmation.Event) error {
			got = append(got, "postconfirmation:"+e.UserName)
			return nil
		}),
	}

	resp, err := h.Handle(context.Background(), raw(presignup.TriggerSignUp))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(resp)
	if !strings.Contains(string(b), `"autoConfirmUser":true`) || !strings.Contains(string(b), `"triggerSource":"PreSignUp_SignUp"`) {
		t.Errorf("response = %s, want the event with the hook's changes", b)
	}

	if _, err := h.Handle(context.Background(), raw(postconfirmation.TriggerConfirmForgotPassword)); err != nil {
		t.Fatal(err)
	}

	if want := []string{"presignup:a@example.com", "postconfirmation:user-1"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v, want %v", got, want)
	}
}

func TestHandle_HookErrorIsReturned(t *testing.T) {
	want := errors.New("denied")
	h := &Handler{PreSignUp: hookFunc[presignup.Event](func(context.Context, *presignup.Event) error { return want })}
	if _, err := h.Handle(context.Background(), raw(presignup.TriggerSignUp)); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

func TestHandle_Errors(t *testing.T) {
	h := &Handler{PostConfirmation: hookFunc[postconfirmation.Event](func(context.Context, *postconfirmation.Event) error { return nil })}

	tests := map[string]json.RawMessage{
		"disabled hook":       raw(presignup.TriggerSignUp),
		"unsupported trigger": raw("PreAuthentication_Authentication"),
		"not json":            json.RawMessage(`not json`),
		"wrong shape":         json.RawMessage(`{"triggerSource":"PostConfirmation_ConfirmSignUp","request":"x"}`),
	}
	for name, ev := range tests {
		t.Run(name, func(t *testing.T) {
			if resp, err := h.Handle(context.Background(), ev); err == nil {
				t.Errorf("Handle() = %v, want an error", resp)
			}
		})
	}
}
