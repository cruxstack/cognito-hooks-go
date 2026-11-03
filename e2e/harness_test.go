// Package e2e tests the function end to end: configuration is read from
// environment variables and wired by app.New exactly as in Lambda, and events
// go through the same handler. Only the Cognito API and the SendGrid API are
// replaced with in-process fakes.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"github.com/cruxstack/cognito-hooks-go/internal/app"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/handler"
)

const policies = "../examples/policies/"

// env is one configured instance of the function and its fakes.
type env struct {
	t        *testing.T
	handler  *handler.Handler
	cognito  *fakeCognito
	sendgrid *fakeSendGrid
}

// newEnv builds the function from vars, which are the environment variables
// Lambda would pass.
func newEnv(t *testing.T, vars map[string]string) *env {
	t.Helper()
	e := &env{t: t, cognito: &fakeCognito{}, sendgrid: newFakeSendGrid(t)}

	all := map[string]string{"APP_SENDGRID_API_HOST": e.sendgrid.URL}
	maps.Copy(all, vars)
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := all[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}

	e.handler, err = app.New(context.Background(), cfg, aws.Config{Region: "us-east-1"},
		app.WithCognitoClient(e.cognito),
	)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// handle sends a raw event through the handler and decodes the response
// into a map.
func (e *env) handle(raw json.RawMessage) (map[string]any, error) {
	e.t.Helper()
	resp, err := e.handler.Handle(context.Background(), raw)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(resp)
	if err != nil {
		e.t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		e.t.Fatal(err)
	}
	return out, nil
}

func (e *env) mustHandle(raw json.RawMessage) map[string]any {
	e.t.Helper()
	out, err := e.handle(raw)
	if err != nil {
		e.t.Fatalf("Handle() = %v", err)
	}
	return out
}

func preSignUpEvent(trigger, clientID, email string) json.RawMessage {
	return event(trigger, clientID, "8a1b2c3d-0000-4000-8000-000000000001", map[string]any{
		"userAttributes": map[string]string{"email": email},
		"validationData": map[string]string{},
		"clientMetadata": map[string]string{},
	}, map[string]any{"autoConfirmUser": false, "autoVerifyEmail": false, "autoVerifyPhone": false})
}

func postConfirmationEvent(trigger, clientID, status string) json.RawMessage {
	return event(trigger, clientID, "8a1b2c3d-0000-4000-8000-000000000001", map[string]any{
		"userAttributes": map[string]string{
			"sub":                 "8a1b2c3d-0000-4000-8000-000000000001",
			"email":               "user@example.com",
			"email_verified":      "true",
			"cognito:user_status": status,
		},
		"clientMetadata": map[string]string{},
	}, map[string]any{})
}

func event(trigger, clientID, userName string, request, response map[string]any) json.RawMessage {
	b, err := json.Marshal(map[string]any{
		"version":       "1",
		"triggerSource": trigger,
		"region":        "us-east-1",
		"userPoolId":    "us-east-1_EXAMPLE",
		"userName":      userName,
		"callerContext": map[string]any{"awsSdkVersion": "aws-sdk-unknown-unknown", "clientId": clientID},
		"request":       request,
		"response":      response,
	})
	if err != nil {
		panic(err)
	}
	return b
}

type fakeCognito struct {
	mu    sync.Mutex
	calls []*cip.AdminSetUserPasswordInput
	err   error
}

func (f *fakeCognito) AdminSetUserPassword(_ context.Context, in *cip.AdminSetUserPasswordInput, _ ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	return &cip.AdminSetUserPasswordOutput{}, nil
}

func (f *fakeCognito) replaced() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	for i, in := range f.calls {
		out[i] = aws.ToString(in.UserPoolId) + "/" + aws.ToString(in.Username)
	}
	return out
}

// fakeSendGrid serves the SendGrid Email Address Validation API.
type fakeSendGrid struct {
	*httptest.Server

	mu          sync.Mutex
	validations []string
	// results maps an address to its validation result ("Valid" by default)
	results map[string]map[string]any
	status  int
}

func newFakeSendGrid(t *testing.T) *fakeSendGrid {
	f := &fakeSendGrid{results: map[string]map[string]any{}, status: http.StatusOK}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeSendGrid) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.URL.Path != "/v3/validations/email" || r.Header.Get("Authorization") != "Bearer SG.verify" {
		http.NotFound(w, r)
		return
	}

	var body map[string]string
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &body)
	f.validations = append(f.validations, body["email"])

	if f.status != http.StatusOK {
		http.Error(w, `{"errors":[{"message":"failed"}]}`, f.status)
		return
	}
	result := f.results[body["email"]]
	if result == nil {
		result = map[string]any{"verdict": "Valid", "score": 0.97}
	}
	result["email"] = body["email"]
	_ = json.NewEncoder(w).Encode(map[string]any{"result": result})
}

// respond sets the validation result for an address.
func (f *fakeSendGrid) respond(email string, result map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[email] = result
}

// fail makes every request fail with status.
func (f *fakeSendGrid) fail(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

func (f *fakeSendGrid) validationCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.validations)
}
