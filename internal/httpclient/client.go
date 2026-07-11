// Package httpclient calls Vota's versioned collector API.
package httpclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/protocol"
)

const maxResponseBytes = 16 << 20

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
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid server URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: parsed, http: httpClient}, nil
}

func (client *Client) PublishPoll(ctx context.Context, manifest protocol.Manifest, adminToken string) (protocol.Manifest, bool, error) {
	var result protocol.Manifest
	status, err := client.doJSON(ctx, http.MethodPost, "/v1/polls", manifest, adminToken, &result)
	return result, status == http.StatusCreated, err
}

func (client *Client) Poll(ctx context.Context, pollID string) (app.PollStatus, error) {
	var result app.PollStatus
	_, err := client.doJSON(ctx, http.MethodGet, "/v1/polls/"+url.PathEscape(pollID), nil, "", &result)
	return result, err
}

func (client *Client) SubmitBallot(ctx context.Context, ballot protocol.BallotEnvelope) (protocol.Receipt, bool, error) {
	var result protocol.Receipt
	status, err := client.doJSON(ctx, http.MethodPost, "/v1/polls/"+url.PathEscape(ballot.PollID)+"/ballots", ballot, "", &result)
	return result, status == http.StatusCreated, err
}

func (client *Client) Receipt(ctx context.Context, pollID, ballotHash string) (protocol.Receipt, error) {
	var result protocol.Receipt
	path := "/v1/polls/" + url.PathEscape(pollID) + "/receipts/" + url.PathEscape(ballotHash)
	_, err := client.doJSON(ctx, http.MethodGet, path, nil, "", &result)
	return result, err
}

func (client *Client) ClosePoll(ctx context.Context, pollID, adminToken string) (protocol.EncryptedAggregate, error) {
	var result protocol.EncryptedAggregate
	_, err := client.doJSON(ctx, http.MethodPost, "/v1/polls/"+url.PathEscape(pollID)+"/close", nil, adminToken, &result)
	return result, err
}

func (client *Client) SubmitTrusteeShare(ctx context.Context, share protocol.TrusteeShare) (*protocol.Tally, bool, error) {
	var result struct {
		Tally *protocol.Tally `json:"tally"`
	}
	status, err := client.doJSON(ctx, http.MethodPost, "/v1/polls/"+url.PathEscape(share.PollID)+"/tally-shares", share, "", &result)
	return result.Tally, status == http.StatusCreated, err
}

func (client *Client) Tally(ctx context.Context, pollID string) (protocol.Tally, error) {
	var result protocol.Tally
	_, err := client.doJSON(ctx, http.MethodGet, "/v1/polls/"+url.PathEscape(pollID)+"/tally", nil, "", &result)
	return result, err
}

func (client *Client) Audit(ctx context.Context, pollID string) ([]byte, error) {
	request, err := client.request(ctx, http.MethodGet, "/v1/polls/"+url.PathEscape(pollID)+"/audit", nil, "")
	if err != nil {
		return nil, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	reader := io.Reader(response.Body)
	if response.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(response.Body)
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("response too large")
	}
	if response.StatusCode >= 400 {
		return nil, decodeError(response.StatusCode, body)
	}
	return body, nil
}

func (client *Client) doJSON(ctx context.Context, method, path string, input any, adminToken string, output any) (int, error) {
	var body []byte
	var err error
	if input != nil {
		body, err = protocol.MarshalCanonical(input)
		if err != nil {
			return 0, err
		}
	}
	request, err := client.request(ctx, method, path, body, adminToken)
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
	}
	return response.StatusCode, nil
}

func (client *Client) request(ctx context.Context, method, path string, body []byte, adminToken string) (*http.Request, error) {
	target := *client.baseURL
	target.Path += path
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if adminToken != "" {
		request.Header.Set("Authorization", "Bearer "+adminToken)
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
