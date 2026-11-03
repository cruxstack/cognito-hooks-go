package sendgrid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func server(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL+"/", "SG.key", nil)
}

func TestValidateEmail(t *testing.T) {
	var gotBody map[string]string
	var gotAuth string
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v3/validations/email" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"result":{"email":"a@example.com","verdict":"Risky","score":0.42,
			"checks":{"domain":{"is_suspected_disposable_address":true},"local_part":{"is_suspected_role_address":true}}}}`)
	})

	v, raw, err := c.ValidateEmail(context.Background(), "a@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer SG.key" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody["email"] != "a@example.com" || gotBody["source"] != "cognito" {
		t.Errorf("request body = %v", gotBody)
	}
	if v.Verdict != VerdictRisky || v.Score != 0.42 || !v.Checks.Domain.IsSuspectedDisposableAddress || !v.Checks.LocalPart.IsSuspectedRoleAddress {
		t.Errorf("validation = %+v", v)
	}
	if len(raw) == 0 {
		t.Error("raw response is empty")
	}
}

// An address is user input; it must not be able to change the request.
func TestValidateEmail_EncodesTheAddress(t *testing.T) {
	var gotBody map[string]string
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &gotBody); err != nil {
			t.Errorf("request body is not valid JSON: %s", b)
		}
		_, _ = io.WriteString(w, `{"result":{"verdict":"Valid","score":1}}`)
	})

	addr := `x@evil.example","email":"ceo@example.com`
	if _, _, err := c.ValidateEmail(context.Background(), addr); err != nil {
		t.Fatal(err)
	}
	if gotBody["email"] != addr {
		t.Errorf("email sent = %q, want %q", gotBody["email"], addr)
	}
}

func TestValidateEmail_Errors(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"errors":[{"message":"unauthorized"}]}`, http.StatusUnauthorized)
		},
		"not json": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "<html>")
		},
		"no verdict": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"errors":[]}`)
		},
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			v, _, err := server(t, h).ValidateEmail(context.Background(), "a@example.com")
			if err == nil || v != nil {
				t.Errorf("ValidateEmail() = %+v, %v; want an error", v, err)
			}
		})
	}

	_, _, err := server(t, tests["status"]).ValidateEmail(context.Background(), "a@example.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("err = %v, want an APIError with status 401", err)
	}
}

func TestValidateEmail_Timeout(t *testing.T) {
	// the server can't see the client hang up without reading the body, so
	// release the handler before closing the server (cleanups run last first)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	c := New(srv.URL, "SG.key", &http.Client{Timeout: 50 * time.Millisecond})
	if _, _, err := c.ValidateEmail(context.Background(), "a@example.com"); err == nil {
		t.Error("expected a timeout error")
	}
}
