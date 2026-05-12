package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

func ParseClaimsJson(_jwt string) (string, error) {

	jwt := strings.TrimSpace(_jwt)

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT: expected 3 parts separated by '.'")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid JWT: failed to decode header")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid JWT: failed to decode claims")
	}

	var headerBuf bytes.Buffer
	if err := json.Indent(&headerBuf, headerBytes, "", "  "); err != nil {
		return "", errors.New("invalid JWT: header is not valid JSON")
	}

	var claimsBuf bytes.Buffer
	if err := json.Indent(&claimsBuf, claimsBytes, "", "  "); err != nil {
		return "", errors.New("invalid JWT: claims is not valid JSON")
	}

	result := "Header:\n" + headerBuf.String() + "\n\nClaims:\n" + claimsBuf.String()
	return result, nil
}
