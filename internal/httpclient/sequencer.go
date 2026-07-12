package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cirocosta/vota/internal/sequencer"
)

func (client *Client) CreateSequencerPoll(ctx context.Context, request sequencer.CreatePollRequest) (sequencer.CreatePollResponse, bool, error) {
	var result sequencer.CreatePollResponse
	status, err := client.doJSON(ctx, http.MethodPost, "/v2/polls", request, "", &result)
	return result, status == http.StatusCreated, err
}

func (client *Client) SequencerPoll(ctx context.Context, pollID string) (sequencer.Poll, error) {
	var result sequencer.Poll
	_, err := client.doJSON(ctx, http.MethodGet, "/v2/polls/"+url.PathEscape(pollID), nil, "", &result)
	return result, err
}

func (client *Client) ClaimCredential(ctx context.Context, pollID string, request sequencer.ClaimRequest) (sequencer.ClaimResponse, bool, error) {
	var result sequencer.ClaimResponse
	status, err := client.doJSON(ctx, http.MethodPost, "/v2/polls/"+url.PathEscape(pollID)+"/credentials", request, "", &result)
	return result, status == http.StatusCreated, err
}

func (client *Client) VoteWithCredential(ctx context.Context, pollID string, request sequencer.BallotRequest) (sequencer.Receipt, bool, error) {
	var result sequencer.Receipt
	status, err := client.doJSON(ctx, http.MethodPost, "/v2/polls/"+url.PathEscape(pollID)+"/ballots", request, "", &result)
	return result, status == http.StatusCreated, err
}

func (client *Client) CloseSequencerPoll(ctx context.Context, pollID string, request sequencer.ClosePollRequest) (sequencer.Tally, error) {
	var result sequencer.Tally
	_, err := client.doJSON(ctx, http.MethodPost, "/v2/polls/"+url.PathEscape(pollID)+"/close", request, "", &result)
	return result, err
}

func (client *Client) SequencerResult(ctx context.Context, pollID string) (sequencer.Tally, error) {
	var result sequencer.Tally
	_, err := client.doJSON(ctx, http.MethodGet, "/v2/polls/"+url.PathEscape(pollID)+"/result", nil, "", &result)
	return result, err
}

func (client *Client) SequencerAudit(ctx context.Context, pollID string) (sequencer.AuditBundle, error) {
	var result sequencer.AuditBundle
	_, err := client.doJSON(ctx, http.MethodGet, "/v2/polls/"+url.PathEscape(pollID)+"/audit", nil, "", &result)
	return result, err
}

// ParsePollURL separates a shareable poll URL into its server base and poll ID.
func ParsePollURL(value string) (string, string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("invalid poll URL")
	}
	marker := "/polls/"
	index := strings.LastIndex(parsed.EscapedPath(), marker)
	if index < 0 {
		return "", "", fmt.Errorf("invalid poll URL")
	}
	pollID, err := url.PathUnescape(parsed.EscapedPath()[index+len(marker):])
	if err != nil || pollID == "" || strings.Contains(pollID, "/") {
		return "", "", fmt.Errorf("invalid poll URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path[:index], "/")
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), pollID, nil
}
