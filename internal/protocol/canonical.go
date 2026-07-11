package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/gowebpki/jcs"
)

// MarshalCanonical returns RFC 8785 canonical JSON.
func MarshalCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize JSON: %w", err)
	}
	return canonical, nil
}

// HashCanonical hashes a domain separator, a zero byte, and canonical JSON.
func HashCanonical(domain string, value any) (string, error) {
	if err := ValidateDomain(domain); err != nil {
		return "", err
	}
	canonical, err := MarshalCanonical(value)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// DecodeStrict rejects duplicate fields, unknown fields, trailing values, and oversized artifacts.
func DecodeStrict(data []byte, target any) error {
	return DecodeStrictLimit(data, target, MaxArtifactBytes)
}

// DecodeStrictLimit applies strict decoding with an explicit transport limit.
func DecodeStrictLimit(data []byte, target any, maxBytes int) error {
	if maxBytes <= 0 || len(data) > maxBytes {
		return validationError("artifact_too_large", "artifact", fmt.Sprintf("artifact exceeds %d bytes", maxBytes))
	}
	if err := rejectDuplicateFields(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return validationError("invalid_json", "artifact", err.Error())
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return validationError("invalid_json", "artifact", err.Error())
	}
	return validationError("trailing_json", "artifact", "artifact contains multiple JSON values")
}

func rejectDuplicateFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder, "$", nil); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func walkJSONValue(decoder *json.Decoder, path string, first json.Token) error {
	token := first
	var err error
	if token == nil {
		token, err = decoder.Token()
		if err != nil {
			return validationError("invalid_json", path, err.Error())
		}
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return validationError("invalid_json", path, err.Error())
			}
			name, ok := nameToken.(string)
			if !ok {
				return validationError("invalid_json", path, "object field is not a string")
			}
			if _, exists := seen[name]; exists {
				return validationError("duplicate_json_field", path+"."+name, "duplicate object field")
			}
			seen[name] = struct{}{}
			if err := walkJSONValue(decoder, path+"."+name, nil); err != nil {
				return err
			}
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := walkJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), nil); err != nil {
				return err
			}
		}
	default:
		return validationError("invalid_json", path, "unexpected JSON delimiter")
	}
	if _, err := decoder.Token(); err != nil {
		return validationError("invalid_json", path, err.Error())
	}
	return nil
}
