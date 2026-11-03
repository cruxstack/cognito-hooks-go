package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/aws/aws-lambda-go/lambdacontext"
)

func TestContextHandler(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewJSONHandler(&buf, slog.LevelInfo))

	ctx := lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{AwsRequestID: "req-1"})
	ctx = WithAttrs(ctx, slog.String("trigger", "PreSignUp_SignUp"))
	ctx = WithAttrs(ctx, slog.String("client_id", "web"))
	log.InfoContext(ctx, "hello", "n", 1)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"msg": "hello", "request_id": "req-1", "trigger": "PreSignUp_SignUp", "client_id": "web", "n": 1.0} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %v", k, rec[k], want)
		}
	}
}

func TestWithAttrs_DoesNotShareBackingArray(t *testing.T) {
	base := WithAttrs(context.Background(), slog.String("a", "1"))
	one := WithAttrs(base, slog.String("b", "1"))
	two := WithAttrs(base, slog.String("b", "2"))

	got1, _ := one.Value(ctxKey{}).([]slog.Attr)
	got2, _ := two.Value(ctxKey{}).([]slog.Attr)
	if got1[1].Value.String() != "1" || got2[1].Value.String() != "2" {
		t.Errorf("attrs leaked between contexts: %v %v", got1, got2)
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "",
		"user@example.com": "u***@example.com",
		"a@b.c":            "a***@b.c",
		"@example.com":     "***",
		"no-at-sign":       "***",
	} {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
