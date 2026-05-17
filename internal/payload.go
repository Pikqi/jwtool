package internal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// modifikacija claimova => uzima jwt i menja mu claimove, pretvara rezultat u base64 payload
func ModifyClaims(jwt string, overrides map[string]string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(jwt), ".", 3)
	if len(parts) != 3 {
		return "", errors.New("Invalid JWT: expected 3 parts")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("Failed to decode payload")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", errors.New("Payload is not valid JSON")
	}

	for k, v := range overrides {
		claims[k] = coerce(v)
	}

	newPayloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("Failed to re-encode payload: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(newPayloadBytes), nil
}

// posto je vrednost flaga --set iz cli string, ovo je metoda za konverziju zbog pravilne validacije
func coerce(v string) interface{} {
	if v == "true" {
		return true
	}
	if v == "false" {
		return false
	}

	var n json.Number
	if err := json.Unmarshal([]byte(v), &n); err == nil {
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			return f
		}
	}

	return v
}
