package internal

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"
	"time"
)

type BruteforceResult struct {
	Secret   string
	Tried    int
	Duration time.Duration
	Alg      string
}

func Bruteforce(_jwt string, wordlist_path string) (BruteforceResult, error) {
	jwt := strings.TrimSpace(_jwt)

	header, err := ParseJWTHeader(_jwt)
	if err != nil {
		return BruteforceResult{}, err
	}

	var h func() hash.Hash
	switch header.Alg {
	case "HS256":
		h = sha256.New
	case "HS384":
		h = sha512.New384
	case "HS512":
		h = sha512.New
	default:
		return BruteforceResult{}, fmt.Errorf("algorithm %s is not supported for brute-forcing", header.Alg)
	}

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

		mac := hmac.New(h, []byte(possible_secret))
		mac.Write(bytes_to_sign)
		possible_signed_bytes := mac.Sum(nil)

		if bytes.Equal(possible_signed_bytes, signatureBytes) {
			return BruteforceResult{
				Secret:   possible_secret,
				Tried:    tried,
				Duration: time.Since(start),
				Alg:      header.Alg,
			}, nil
		}
	}

	return BruteforceResult{
		Secret:   "",
		Tried:    tried,
		Duration: time.Since(start),
		Alg:      header.Alg,
	}, nil
}
