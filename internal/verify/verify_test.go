package verify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cruxstack/cognito-hooks-go/internal/sendgrid"
)

type stubVerifier struct {
	calls int
	err   error
}

func (s *stubVerifier) Verify(context.Context, string) (*Result, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &Result{Provider: "stub", Valid: true, Verdict: VerdictValid, Score: 0.5}, nil
}

func TestAllowlist(t *testing.T) {
	next := &stubVerifier{}
	v := Allowlist{Domains: []string{"example.com"}, Next: next}

	for _, email := range []string{"user@example.com", "User@EXAMPLE.com", "Jane <jane@example.com>"} {
		r, err := v.Verify(context.Background(), email)
		if err != nil {
			t.Fatal(err)
		}
		if r.Provider != ProviderAllowlist || !r.Valid || r.Score != 1 {
			t.Errorf("%s: result = %+v, want an allowlist result", email, r)
		}
	}
	if next.calls != 0 {
		t.Errorf("next called %d times for allowlisted domains", next.calls)
	}

	for _, email := range []string{"user@sub.example.com", "user@example.com.evil.test", "not an address"} {
		r, err := v.Verify(context.Background(), email)
		if err != nil {
			t.Fatal(err)
		}
		if r.Provider != "stub" {
			t.Errorf("%s: provider = %q, want the next verifier", email, r.Provider)
		}
	}
}

func TestAllowlist_PassesErrorsThrough(t *testing.T) {
	want := errors.New("unavailable")
	v := Allowlist{Domains: []string{"example.com"}, Next: &stubVerifier{err: want}}
	if _, err := v.Verify(context.Background(), "user@other.test"); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}

func TestSendGrid(t *testing.T) {
	tests := map[string]struct {
		body string
		want Result
	}{
		"valid": {
			body: `{"result":{"verdict":"Valid","score":0.97}}`,
			want: Result{Provider: ProviderSendGrid, Valid: true, Verdict: VerdictValid, Score: 0.97},
		},
		"risky disposable role": {
			body: `{"result":{"verdict":"Risky","score":0.3,"checks":{"domain":{"is_suspected_disposable_address":true},"local_part":{"is_suspected_role_address":true}}}}`,
			want: Result{Provider: ProviderSendGrid, Valid: true, Verdict: VerdictRisky, Score: 0.3, Disposable: true, Role: true},
		},
		"invalid": {
			body: `{"result":{"verdict":"Invalid","score":0.01}}`,
			want: Result{Provider: ProviderSendGrid, Valid: false, Verdict: VerdictInvalid, Score: 0.01},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			r, err := SendGrid{Client: sendgrid.New(srv.URL, "SG.key", nil)}.Verify(context.Background(), "user@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if r.Raw != tt.body {
				t.Errorf("raw = %q, want the response body", r.Raw)
			}
			r.Raw = ""
			if *r != tt.want {
				t.Errorf("result = %+v, want %+v", *r, tt.want)
			}
		})
	}
}

func TestSendGrid_ErrorStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"message":"unauthorized"}]}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	r, err := SendGrid{Client: sendgrid.New(srv.URL, "SG.key", nil)}.Verify(context.Background(), "user@example.com")
	if err == nil {
		t.Fatalf("result = %+v, want an error", r)
	}
}

func TestDomain(t *testing.T) {
	for in, want := range map[string]string{
		"user@example.com":           "example.com",
		"Jane <jane@Example.COM>":    "Example.COM",
		`"odd@local"@example.com`:    "example.com",
		"not an address":             "",
		"user@":                      "",
		"invalid..dots@exa mple.com": "",
	} {
		got, ok := Domain(in)
		if got != want || ok != (want != "") {
			t.Errorf("Domain(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
