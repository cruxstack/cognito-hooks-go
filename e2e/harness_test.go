// Package e2e tests the function end to end: configuration is read from
// environment variables and wired by app.New exactly as in Lambda, and events
// go through the same handler. Only the Cognito, DynamoDB, and SendGrid APIs
// are replaced with in-process fakes.
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

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
	dynamodb *fakeDynamoDB
	sendgrid *fakeSendGrid
}

// newEnv builds the function from vars, which are the environment variables
// Lambda would pass.
func newEnv(t *testing.T, vars map[string]string) *env {
	t.Helper()
	return newEnvWith(t, vars, newFakeDynamoDB())
}

// newEnvWith builds the function with an existing DynamoDB fake, as a new
// deployment with the same rotation table would see it.
func newEnvWith(t *testing.T, vars map[string]string, ddb *fakeDynamoDB) *env {
	t.Helper()
	e := &env{t: t, cognito: &fakeCognito{}, dynamodb: ddb, sendgrid: newFakeSendGrid(t)}

	all := map[string]string{"APP_SENDGRID_API_HOST": e.sendgrid.URL}
	maps.Copy(all, vars)
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := all[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}

	e.handler, err = app.New(context.Background(), cfg, aws.Config{Region: "us-east-1"},
		app.WithCognitoClient(e.cognito),
		app.WithDynamoDBClient(e.dynamodb),
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

func preAuthenticationEvent(userName string, attrs map[string]string, userNotFound bool) json.RawMessage {
	return event("PreAuthentication_Authentication", "1example23456789", userName, map[string]any{
		"userAttributes": attrs,
		"validationData": map[string]string{},
		"userNotFound":   userNotFound,
	}, map[string]any{})
}

// signIn is a PreAuthentication event for a native user with a status.
func signIn(sub, status string) json.RawMessage {
	return preAuthenticationEvent(sub, map[string]string{
		"sub":                 sub,
		"email":               "user@example.com",
		"email_verified":      "true",
		"cognito:user_status": status,
	}, false)
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

	// users are the users AdminGetUser finds, by username
	users   map[string]*cip.AdminGetUserOutput
	lookups int
}

func (f *fakeCognito) AdminGetUser(_ context.Context, in *cip.AdminGetUserInput, _ ...func(*cip.Options)) (*cip.AdminGetUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if u, ok := f.users[aws.ToString(in.Username)]; ok {
		return u, nil
	}
	return nil, errors.New("UserNotFoundException: User does not exist.")
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

// fakeDynamoDB stores items by table and sub, as the rotation table does.
type fakeDynamoDB struct {
	mu       sync.Mutex
	items    map[string]map[string]ddbtypes.AttributeValue
	getErr   error
	putErr   error
	gets     int
	putCount int
}

func newFakeDynamoDB() *fakeDynamoDB {
	return &fakeDynamoDB{items: map[string]map[string]ddbtypes.AttributeValue{}}
}

func itemKey(table string, key map[string]ddbtypes.AttributeValue) string {
	sub, _ := key["sub"].(*ddbtypes.AttributeValueMemberS)
	if sub == nil {
		return table + "/"
	}
	return table + "/" + sub.Value
}

func (f *fakeDynamoDB) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &dynamodb.GetItemOutput{Item: f.items[itemKey(aws.ToString(in.TableName), in.Key)]}, nil
}

func (f *fakeDynamoDB) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putCount++
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.items[itemKey(aws.ToString(in.TableName), in.Item)] = in.Item
	return &dynamodb.PutItemOutput{}, nil
}

// replacedAt returns the recorded replacement time of a user, if any.
func (f *fakeDynamoDB) replacedAt(table, sub string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	item, ok := f.items[table+"/"+sub]
	if !ok {
		return time.Time{}, false
	}
	v, _ := item["replaced_at"].(*ddbtypes.AttributeValueMemberS)
	if v == nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, v.Value)
	return t, err == nil
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
