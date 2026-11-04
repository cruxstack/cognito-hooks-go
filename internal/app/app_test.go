package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/preauthentication"
)

// throttlingAWS answers every Cognito and DynamoDB request with a throttling
// error and counts the requests per operation.
type throttlingAWS struct {
	mu    sync.Mutex
	calls map[string]int
}

func (s *throttlingAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("X-Amz-Target")
	s.mu.Lock()
	s.calls[target]++
	s.mu.Unlock()

	switch {
	case strings.HasPrefix(target, "AWSCognitoIdentityProviderService."):
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"__type":"TooManyRequestsException","message":"Rate exceeded"}`)
	case strings.HasPrefix(target, "DynamoDB_20120810."):
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"__type":"com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException","message":"Rate exceeded"}`)
	default:
		http.NotFound(w, r)
	}
}

// The real SDK clients retry a throttled call once, soon, so a throttled
// sign-in is rejected by the hook well within Cognito's 5 seconds.
func TestNew_ClientsRetryThrottledCallsOnce(t *testing.T) {
	fake := &throttlingAWS{calls: map[string]int{}}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)

	cfg, err := config.Load(func(k string) (string, bool) {
		v, ok := map[string]string{
			"APP_LOG_LEVEL":                        "error",
			"APP_PREAUTHENTICATION_ENABLED":        "true",
			"APP_PREAUTHENTICATION_ROTATE_BEFORE":  "2026-11-01T00:00:00Z",
			"APP_PREAUTHENTICATION_ROTATION_TABLE": "rotations",
		}[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(context.Background(), cfg, aws.Config{
		Region:       "us-east-1",
		Credentials:  aws.AnonymousCredentials{},
		BaseEndpoint: aws.String(srv.URL),
	})
	if err != nil {
		t.Fatal(err)
	}

	event, _ := json.Marshal(map[string]any{
		"version":       "1",
		"triggerSource": "PreAuthentication_Authentication",
		"region":        "us-east-1",
		"userPoolId":    "us-east-1_EXAMPLE",
		"userName":      "8a1b2c3d-0000-4000-8000-000000000001",
		"callerContext": map[string]string{"clientId": "1example23456789"},
		"request": map[string]any{
			"userAttributes": map[string]string{
				"sub":                 "8a1b2c3d-0000-4000-8000-000000000001",
				"cognito:user_status": "CONFIRMED",
			},
			"validationData": map[string]string{},
			"userNotFound":   false,
		},
		"response": map[string]any{},
	})

	start := time.Now()
	_, err = h.Handle(context.Background(), event)
	if !errors.Is(err, preauthentication.ErrUnavailable) {
		t.Errorf("Handle() = %v, want ErrUnavailable", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Handle() took %v", d)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	for target, want := range map[string]int{
		// the unreadable record is treated as stale, so the password is
		// replaced, and the throttled replacement rejects the sign-in
		"DynamoDB_20120810.GetItem":                              MaxAttempts,
		"AWSCognitoIdentityProviderService.AdminSetUserPassword": MaxAttempts,
		"DynamoDB_20120810.PutItem":                              0,
	} {
		if got := fake.calls[target]; got != want {
			t.Errorf("%s requests = %d, want %d (all: %v)", target, got, want, fake.calls)
		}
	}
}
