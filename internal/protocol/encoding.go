package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DecodeFixedHex decodes a prefixed lowercase hex value with an exact byte size.
func DecodeFixedHex(prefix, value string, byteLength int) ([]byte, error) {
	if byteLength < 0 {
		return nil, errors.New("byte length must be non-negative")
	}
	payload, ok := strings.CutPrefix(value, prefix+":")
	if !ok {
		return nil, fmt.Errorf("expected %s prefix", prefix)
	}
	return decodeHexPayload(payload, byteLength, "")
}

// DecodeOpaqueHex decodes a prefixed non-empty lowercase hex value.
func DecodeOpaqueHex(prefix, value string) ([]byte, error) {
	payload, ok := strings.CutPrefix(value, prefix+":")
	if !ok {
		return nil, fmt.Errorf("expected %s prefix", prefix)
	}
	return decodeHexPayload(payload, -1, "opaque value must contain non-empty even-length hex")
}

// DecodeRawHex decodes an unprefixed lowercase hex value.
//
// A non-negative byteLength requires an exact decoded size. A negative
// byteLength accepts any non-empty even-length value.
func DecodeRawHex(value string, byteLength int) ([]byte, error) {
	message := ""
	if byteLength < 0 {
		message = "hex value must contain non-empty even-length hex"
	}
	return decodeHexPayload(value, byteLength, message)
}

// ParseCanonicalTime parses normalized UTC RFC3339 timestamps.
func ParseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	if parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("time must be normalized UTC RFC3339")
	}
	return parsed, nil
}

func decodeHexPayload(payload string, byteLength int, variableMessage string) ([]byte, error) {
	if variableMessage != "" {
		if len(payload) < 2 || len(payload)%2 != 0 {
			return nil, errors.New(variableMessage)
		}
	} else if len(payload) != byteLength*2 {
		return nil, fmt.Errorf("expected %d encoded bytes", byteLength)
	}
	decoded, err := hex.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if payload != strings.ToLower(payload) {
		return nil, errors.New("hex must be lowercase")
	}
	return decoded, nil
}
