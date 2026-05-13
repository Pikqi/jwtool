package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const (
	colorOrange = "\033[38;5;208m"
	colorPurple = "\033[13;5;95m"
	colorGreen  = "\033[32m"
	colorReset  = "\033[0m"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func ParseJWTHeader(_jwt string) (JWTHeader, error) {
	jwt := strings.TrimSpace(_jwt)

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return JWTHeader{}, errors.New("invalid JWT: expected 3 parts separated by '.'")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return JWTHeader{}, errors.New("invalid JWT: failed to decode header")
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return JWTHeader{}, errors.New("invalid JWT: header is not valid JSON")
	}

	return header, nil
}

func FormatJWT(_jwt string, color bool) (string, error) {
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

	var coloredJWT string
	if color {
		coloredJWT = colorOrange + parts[0] + colorReset + "." + colorPurple + parts[1] + colorReset + "." + colorGreen + parts[2] + colorReset
	} else {
		coloredJWT = jwt
	}

	result := ""
	if color {
		result = coloredJWT + "\n\nHeader:\n" + colorOrange + headerBuf.String() + colorReset +
			"\n\nClaims:\n" + colorPurple + claimsBuf.String() + colorReset
	} else {
		result = coloredJWT + "\n\nHeader:\n" + headerBuf.String() +
			"\n\nClaims:\n" + claimsBuf.String()

	}

	return result, nil
}
