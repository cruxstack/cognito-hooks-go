// Package sendgrid is a minimal client for the SendGrid v3 Email Address
// Validation API.
package sendgrid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the global SendGrid API host. Accounts with EU data
// residency use https://api.eu.sendgrid.com.
const DefaultBaseURL = "https://api.sendgrid.com"

// DefaultTimeout bounds each request. Cognito waits at most 5 seconds for a
// trigger, so a slow validation must not use up that time.
const DefaultTimeout = 3 * time.Second

const (
	pathValidateEmail = "/v3/validations/email"

	// maxErrorBody bounds how much of an error response is kept
	maxErrorBody = 4 << 10
)

// Verdicts returned by the Email Address Validation API.
const (
	VerdictValid   = "Valid"
	VerdictRisky   = "Risky"
	VerdictInvalid = "Invalid"
)

// Client calls the SendGrid API with one API key.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// New returns a client for baseURL (DefaultBaseURL when empty). A nil
// httpClient uses a client with DefaultTimeout.
func New(baseURL, apiKey string, httpClient *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: httpClient}
}

// APIError is a non-2xx response from the SendGrid API.
type APIError struct {
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sendgrid %s returned status %d: %s", e.Path, e.StatusCode, e.Body)
}

// Validation is the result of validating one email address.
type Validation struct {
	Email   string  `json:"email"`
	Verdict string  `json:"verdict"`
	Score   float64 `json:"score"`
	Checks  struct {
		Domain struct {
			HasValidAddressSyntax        bool `json:"has_valid_address_syntax"`
			HasMXOrARecord               bool `json:"has_mx_or_a_record"`
			IsSuspectedDisposableAddress bool `json:"is_suspected_disposable_address"`
		} `json:"domain"`
		LocalPart struct {
			IsSuspectedRoleAddress bool `json:"is_suspected_role_address"`
		} `json:"local_part"`
		Additional struct {
			HasKnownBounces     bool `json:"has_known_bounces"`
			HasSuspectedBounces bool `json:"has_suspected_bounces"`
		} `json:"additional"`
	} `json:"checks"`
}

// ValidateEmail validates one address. It returns the parsed result and the
// raw response body.
func (c *Client) ValidateEmail(ctx context.Context, email string) (*Validation, []byte, error) {
	body, err := json.Marshal(map[string]string{"email": email, "source": "cognito"})
	if err != nil {
		return nil, nil, fmt.Errorf("encode sendgrid request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+pathValidateEmail, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("build sendgrid request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sendgrid %s: %w", pathValidateEmail, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, nil, &APIError{Path: pathValidateEmail, StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read sendgrid %s response: %w", pathValidateEmail, err)
	}

	var out struct {
		Result *Validation `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, raw, fmt.Errorf("decode sendgrid validation response: %w", err)
	}
	if out.Result == nil || out.Result.Verdict == "" {
		return nil, raw, fmt.Errorf("sendgrid validation response has no verdict")
	}
	return out.Result, raw, nil
}
