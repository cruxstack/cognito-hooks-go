// Command devtool runs Cognito hook events locally.
//
//	devtool eval -events events.json -presignup-policy policy.rego
//	    Evaluate policies against events and print each decision. Makes no
//	    AWS or network calls.
//
//	devtool run -events events.json
//	    Run events through the whole function with the configuration from the
//	    environment and .env, and print each response. Passwords are not
//	    changed, and rotation records not read or written, unless you pass
//	    -live.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"

	"github.com/joho/godotenv"

	"github.com/cruxstack/cognito-hooks-go/internal/logging"
)

const usage = `usage: devtool <command> [flags]

commands:
  eval   evaluate policies against events and print the decisions
  run    run events through the whole function (dry run by default)

run "devtool <command> -h" for the flags of a command`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	ctx := context.Background()
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "eval":
		err = evalCmd(ctx, args, os.Stdout)
	case "run":
		err = runCmd(ctx, args, os.Stdout)
	case "-h", "--help", "help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

// header is the part of an event that identifies its trigger.
type header struct {
	TriggerSource string `json:"triggerSource"`
}

// readEvents reads a JSON file with one event object or an array of events.
func readEvents(path string) ([]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '{' {
		return []json.RawMessage{data}, nil
	}
	var events []json.RawMessage
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("%s: want an event object or an array of events: %w", path, err)
	}
	return events, nil
}

// loadDotEnv loads path into the environment without overriding variables
// that are already set. A missing file is ignored.
func loadDotEnv(path string) error {
	if path == "" {
		return nil
	}
	if err := godotenv.Load(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("load %s: %w", path, err)
	}
	return nil
}

func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(logging.ContextHandler(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})))
}

func newEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc
}
