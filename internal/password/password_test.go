package password

import (
	"strings"
	"testing"
)

func TestGenerateLengthAndClasses(t *testing.T) {
	for range 200 {
		p, err := Generate(64)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(p) != 64 {
			t.Fatalf("length = %d, want 64", len(p))
		}
		for _, set := range classes {
			if !strings.ContainsAny(p, set) {
				t.Fatalf("password %q has no character from %q", p, set)
			}
		}
	}
}

func TestGenerateIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		p, err := Generate(64)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if seen[p] {
			t.Fatalf("duplicate password generated")
		}
		seen[p] = true
	}
}

func TestGenerateRejectsShortLength(t *testing.T) {
	if _, err := Generate(3); err == nil {
		t.Fatal("expected an error for a length shorter than the class count")
	}
}
