package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/cirocosta/vota/internal/protocol"
)

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := protocol.MarshalCanonical(value)
	if err != nil {
		encoded = []byte(`{"error":{"code":"internal_error","message":"internal server error","request_id":""}}`)
		status = http.StatusInternalServerError
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(value[:])
}

type requestIDKey struct{}

func requestID(request *http.Request) string {
	if value, ok := request.Context().Value(requestIDKey{}).(string); ok {
		return value
	}
	return newRequestID()
}
