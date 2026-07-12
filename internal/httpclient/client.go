// Package httpclient calls Vota's sequencer API.
package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cirocosta/vota/internal/protocol"
)

const maxResponseBytes = 32 << 20

type Client struct {
	baseURL *url.URL
	http    *http.Client
}

type Error struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *Error) Error() string {
	return fmt.Sprintf("http %d %s: %s", e.Status, e.Code, e.Message)
}

func New(baseURL string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || !isHTTPURL(parsed) {
		return nil, fmt.Errorf("invalid server URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: parsed, http: httpClient}, nil
}

func isHTTPURL(parsed *url.URL) bool {
	return parsed != nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Opaque == ""
}

func (client *Client) doJSON(ctx context.Context, method, path string, input any, _ string, output any) (int, error) {
	var body []byte
	var err error
	if input != nil {
		body, err = protocol.MarshalCanonical(input)
		if err != nil {
			return 0, err
		}
	}
	request, err := client.request(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return response.StatusCode, err
	}
	if len(responseBody) > maxResponseBytes {
		return response.StatusCode, fmt.Errorf("response too large")
	}
	if response.StatusCode >= 400 {
		return response.StatusCode, decodeError(response.StatusCode, responseBody)
	}
	if output != nil {
		if err := protocol.DecodeStrict(responseBody, output); err != nil {
			return response.StatusCode, fmt.Errorf("decode response: %w", err)
		}
		canonical, err := protocol.MarshalCanonical(output)
		if err != nil || !bytes.Equal(responseBody, canonical) {
			return response.StatusCode, fmt.Errorf("decode response: noncanonical JSON")
		}
	}
	return response.StatusCode, nil
}

func (client *Client) request(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	target := *client.baseURL
	target.Path += path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func decodeError(status int, body []byte) error {
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error.Code == "" {
		return &Error{Status: status, Code: "invalid_error_response", Message: http.StatusText(status)}
	}
	return &Error{Status: status, Code: envelope.Error.Code, Message: envelope.Error.Message, RequestID: envelope.Error.RequestID}
}
