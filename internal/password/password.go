package password

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{}<>?"
)

var classes = []string{lower, upper, digits, symbols}

// Generate returns a random password of the given length that contains at
// least one lowercase letter, uppercase letter, digit, and symbol, so it meets
// any Cognito password policy that the length satisfies.
func Generate(length int) (string, error) {
	if length < len(classes) {
		return "", errors.New("password length must cover every character class")
	}

	all := lower + upper + digits + symbols
	out := make([]byte, length)
	for i := range out {
		set := all
		if i < len(classes) {
			set = classes[i]
		}
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		out[i] = c
	}

	// shuffle so the guaranteed classes aren't always at the front
	for i := len(out) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		out[i], out[j.Int64()] = out[j.Int64()], out[i]
	}

	return string(out), nil
}

func pick(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}
