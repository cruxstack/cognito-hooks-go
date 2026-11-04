// Package handler is the Lambda entry point: it decodes a Cognito trigger
// event and routes it to the hook for its trigger source.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/cruxstack/cognito-hooks-go/internal/logging"
	"github.com/cruxstack/cognito-hooks-go/internal/postconfirmation"
	"github.com/cruxstack/cognito-hooks-go/internal/preauthentication"
	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
)

// Hook handles the events of one Cognito trigger. Handle may change the
// event; the changed event is the response to Cognito.
type Hook[E any] interface {
	Handle(ctx context.Context, e *E) error
}

// Handler holds the enabled hooks. A nil hook is disabled.
type Handler struct {
	PreSignUp         Hook[presignup.Event]
	PostConfirmation  Hook[postconfirmation.Event]
	PreAuthentication Hook[preauthentication.Event]
}

// Handle decodes one event, routes it to its hook, and returns the event the
// hook responded with.
//
// An event for a disabled hook or an unknown trigger is an error. Cognito
// triggers are synchronous, so the error reaches the user (a PreSignUp error
// rejects the sign-up, and a PreAuthentication error the sign-in) and points
// at the misconfiguration, instead of letting events through unchecked.
func (h *Handler) Handle(ctx context.Context, raw json.RawMessage) (any, error) {
	var hdr events.CognitoEventUserPoolsHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		slog.ErrorContext(ctx, "failed to decode event", "error", err)
		return nil, fmt.Errorf("decode event: %w", err)
	}

	// every log record for this event carries these attributes
	ctx = logging.WithAttrs(ctx,
		slog.String("trigger", hdr.TriggerSource),
		slog.String("user_pool_id", hdr.UserPoolID),
		slog.String("client_id", hdr.CallerContext.ClientID),
	)
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		var compact bytes.Buffer
		if json.Compact(&compact, raw) == nil {
			slog.DebugContext(ctx, "received event", "event", json.RawMessage(compact.Bytes()))
		}
	}

	switch t := hdr.TriggerSource; {
	case strings.HasPrefix(t, presignup.TriggerPrefix):
		return dispatch(ctx, raw, h.PreSignUp)
	case strings.HasPrefix(t, postconfirmation.TriggerPrefix):
		return dispatch(ctx, raw, h.PostConfirmation)
	case strings.HasPrefix(t, preauthentication.TriggerPrefix):
		return dispatch(ctx, raw, h.PreAuthentication)
	default:
		slog.ErrorContext(ctx, "unsupported trigger source")
		return nil, fmt.Errorf("trigger source %q is not supported", t)
	}
}

func dispatch[E any](ctx context.Context, raw json.RawMessage, hook Hook[E]) (any, error) {
	if hook == nil {
		slog.ErrorContext(ctx, "the hook for this trigger is not enabled")
		return nil, fmt.Errorf("the hook for this trigger is not enabled")
	}

	e := new(E)
	if err := json.Unmarshal(raw, e); err != nil {
		slog.ErrorContext(ctx, "failed to decode event", "error", err)
		return nil, fmt.Errorf("decode event: %w", err)
	}
	if err := hook.Handle(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}
