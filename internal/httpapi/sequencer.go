package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cirocosta/vota/internal/protocol"
	"github.com/cirocosta/vota/internal/sequencer"
)

type SequencerConfig struct {
	Service        *sequencer.Service
	PublicBaseURL  string
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	Logger         *slog.Logger
}

type SequencerAPI struct {
	service        *sequencer.Service
	publicBaseURL  string
	maxBodyBytes   int64
	requestTimeout time.Duration
	logger         *slog.Logger
	mux            *http.ServeMux
	metrics        SequencerMetrics
}

type SequencerMetrics struct {
	PollsCreated         atomic.Uint64
	ClaimAttempts        atomic.Uint64
	ClaimsAccepted       atomic.Uint64
	DuplicateClaims      atomic.Uint64
	VoteAttempts         atomic.Uint64
	VotesAccepted        atomic.Uint64
	DuplicateRedemptions atomic.Uint64
	Closes               atomic.Uint64
	AuditExports         atomic.Uint64
}

type SequencerMetricsSnapshot struct {
	PollsCreated         uint64 `json:"polls_created"`
	ClaimAttempts        uint64 `json:"claim_attempts"`
	ClaimsAccepted       uint64 `json:"claims_accepted"`
	DuplicateClaims      uint64 `json:"duplicate_claims"`
	VoteAttempts         uint64 `json:"vote_attempts"`
	VotesAccepted        uint64 `json:"votes_accepted"`
	DuplicateRedemptions uint64 `json:"duplicate_redemptions"`
	Closes               uint64 `json:"closes"`
	AuditExports         uint64 `json:"audit_exports"`
}

func (api *SequencerAPI) Metrics() SequencerMetricsSnapshot {
	return SequencerMetricsSnapshot{
		PollsCreated: api.metrics.PollsCreated.Load(), ClaimAttempts: api.metrics.ClaimAttempts.Load(),
		ClaimsAccepted: api.metrics.ClaimsAccepted.Load(), DuplicateClaims: api.metrics.DuplicateClaims.Load(),
		VoteAttempts: api.metrics.VoteAttempts.Load(), VotesAccepted: api.metrics.VotesAccepted.Load(),
		DuplicateRedemptions: api.metrics.DuplicateRedemptions.Load(), Closes: api.metrics.Closes.Load(),
		AuditExports: api.metrics.AuditExports.Load(),
	}
}

func NewSequencer(config SequencerConfig) (*SequencerAPI, error) {
	if config.Service == nil {
		return nil, errors.New("nil sequencer service")
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 1 << 20
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 15 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if config.PublicBaseURL != "" {
		parsed, err := url.Parse(config.PublicBaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, errors.New("invalid public base URL")
		}
		config.PublicBaseURL = strings.TrimRight(config.PublicBaseURL, "/")
	}
	api := &SequencerAPI{service: config.Service, publicBaseURL: config.PublicBaseURL, maxBodyBytes: config.MaxBodyBytes, requestTimeout: config.RequestTimeout, logger: config.Logger, mux: http.NewServeMux()}
	api.routes()
	return api, nil
}

func (api *SequencerAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	requestID := newRequestID()
	ctx, cancel := context.WithTimeout(request.Context(), api.requestTimeout)
	defer cancel()
	request = request.WithContext(context.WithValue(ctx, requestIDKey{}, requestID))
	recorder := &sequencerRecorder{ResponseWriter: response, status: http.StatusOK}
	api.mux.ServeHTTP(recorder, request)
	api.logger.InfoContext(ctx, "http request",
		"request_id", requestID,
		"method", request.Method,
		"route", request.Pattern,
		"status", recorder.status,
		"duration_bucket", durationBucket(time.Since(started)),
		"error_code", recorder.errorCode,
	)
}

func (api *SequencerAPI) routes() {
	api.mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
	})
	api.mux.HandleFunc("GET /readyz", api.ready)
	api.mux.HandleFunc("GET /metrics", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, api.Metrics())
	})
	api.mux.HandleFunc("POST /v2/polls", api.createPoll)
	api.mux.HandleFunc("GET /v2/polls/{poll_id}", api.getPoll)
	api.mux.HandleFunc("POST /v2/polls/{poll_id}/credentials", api.claim)
	api.mux.HandleFunc("POST /v2/polls/{poll_id}/ballots", api.vote)
	api.mux.HandleFunc("POST /v2/polls/{poll_id}/close", api.closePollV2)
	api.mux.HandleFunc("GET /v2/polls/{poll_id}/result", api.result)
	api.mux.HandleFunc("GET /v2/polls/{poll_id}/audit", api.auditV2)
	api.mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		api.error(response, request, http.StatusNotFound, "not_found")
	})
}

func (api *SequencerAPI) ready(response http.ResponseWriter, request *http.Request) {
	if err := api.service.Ready(request.Context()); err != nil {
		api.error(response, request, http.StatusServiceUnavailable, "not_ready")
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
}

func (api *SequencerAPI) createPoll(response http.ResponseWriter, request *http.Request) {
	var input sequencer.CreatePollRequest
	if !api.decode(response, request, &input) {
		return
	}
	poll, created, err := api.service.CreatePoll(request.Context(), input)
	if err != nil {
		api.serviceError(response, request, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		api.metrics.PollsCreated.Add(1)
	}
	pollURL := api.publicBaseURL + "/polls/" + url.PathEscape(poll.PollID)
	writeJSON(response, status, sequencer.CreatePollResponse{Poll: poll, PollURL: pollURL})
}

func (api *SequencerAPI) getPoll(response http.ResponseWriter, request *http.Request) {
	poll, err := api.service.Poll(request.Context(), request.PathValue("poll_id"))
	if err != nil {
		api.serviceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, poll)
}

func (api *SequencerAPI) claim(response http.ResponseWriter, request *http.Request) {
	api.metrics.ClaimAttempts.Add(1)
	var input sequencer.ClaimRequest
	if !api.decode(response, request, &input) {
		return
	}
	result, created, err := api.service.Claim(request.Context(), request.PathValue("poll_id"), input)
	if err != nil {
		if code := sequencer.ErrorCode(err); code == "credit_already_claimed" || code == "issuance_request_mismatch" {
			api.metrics.DuplicateClaims.Add(1)
		}
		api.serviceError(response, request, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		api.metrics.ClaimsAccepted.Add(1)
	}
	writeJSON(response, status, result)
}

func (api *SequencerAPI) vote(response http.ResponseWriter, request *http.Request) {
	api.metrics.VoteAttempts.Add(1)
	var input sequencer.BallotRequest
	if !api.decode(response, request, &input) {
		return
	}
	receipt, created, err := api.service.Vote(request.Context(), request.PathValue("poll_id"), input)
	if err != nil {
		if sequencer.ErrorCode(err) == "credential_already_spent" {
			api.metrics.DuplicateRedemptions.Add(1)
		}
		api.serviceError(response, request, err)
		return
	}
	status := http.StatusOK
	if created {
		api.metrics.VotesAccepted.Add(1)
		status = http.StatusCreated
	}
	writeJSON(response, status, receipt)
}

func (api *SequencerAPI) closePollV2(response http.ResponseWriter, request *http.Request) {
	var input sequencer.ClosePollRequest
	if !api.decode(response, request, &input) {
		return
	}
	tally, created, err := api.service.ClosePoll(request.Context(), request.PathValue("poll_id"), input)
	if err != nil {
		api.serviceError(response, request, err)
		return
	}
	if created {
		api.metrics.Closes.Add(1)
	}
	writeJSON(response, http.StatusOK, tally)
}

func (api *SequencerAPI) result(response http.ResponseWriter, request *http.Request) {
	tally, err := api.service.Result(request.Context(), request.PathValue("poll_id"))
	if err != nil {
		api.serviceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, tally)
}

func (api *SequencerAPI) auditV2(response http.ResponseWriter, request *http.Request) {
	bundle, err := api.service.Audit(request.Context(), request.PathValue("poll_id"))
	if err != nil {
		api.serviceError(response, request, err)
		return
	}
	api.metrics.AuditExports.Add(1)
	writeJSON(response, http.StatusOK, bundle)
}

func (api *SequencerAPI) decode(response http.ResponseWriter, request *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		api.error(response, request, http.StatusUnsupportedMediaType, "unsupported_content_type")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, api.maxBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			api.error(response, request, http.StatusRequestEntityTooLarge, "request_too_large")
		} else {
			api.error(response, request, http.StatusBadRequest, "invalid_request_body")
		}
		return false
	}
	if err := protocol.DecodeStrictLimit(body, target, int(api.maxBodyBytes)); err != nil {
		api.error(response, request, http.StatusUnprocessableEntity, "invalid_json")
		return false
	}
	canonical, err := protocol.MarshalCanonical(target)
	if err != nil || !bytes.Equal(body, canonical) {
		api.error(response, request, http.StatusUnprocessableEntity, "noncanonical_json")
		return false
	}
	return true
}

func (api *SequencerAPI) serviceError(response http.ResponseWriter, request *http.Request, err error) {
	code := sequencer.ErrorCode(err)
	api.error(response, request, sequencerStatus(code), code)
}

func (api *SequencerAPI) error(response http.ResponseWriter, request *http.Request, status int, code string) {
	if recorder, ok := response.(*sequencerRecorder); ok {
		recorder.errorCode = code
	}
	writeJSON(response, status, errorEnvelope{Error: errorBody{Code: code, Message: sequencerPublicMessage(code), RequestID: requestID(request)}})
}

func sequencerStatus(code string) int {
	switch code {
	case "poll_not_found":
		return http.StatusNotFound
	case "admin_not_authorized", "not_eligible":
		return http.StatusForbidden
	case "credit_already_claimed", "issuance_request_mismatch", "credential_already_spent", "poll_conflict":
		return http.StatusConflict
	case "poll_not_open", "poll_not_closed", "result_unavailable", "invalid_choice", "invalid_credential":
		return http.StatusUnprocessableEntity
	default:
		if strings.HasPrefix(code, "invalid_") || strings.HasPrefix(code, "wrong_") || strings.HasPrefix(code, "unsupported_") || strings.HasPrefix(code, "duplicate_") {
			return http.StatusUnprocessableEntity
		}
		return http.StatusInternalServerError
	}
}

func sequencerPublicMessage(code string) string {
	if sequencerStatus(code) >= 500 {
		return "internal server error"
	}
	return strings.ReplaceAll(code, "_", " ")
}

func durationBucket(duration time.Duration) string {
	switch {
	case duration < 10*time.Millisecond:
		return "lt_10ms"
	case duration < 100*time.Millisecond:
		return "lt_100ms"
	case duration < time.Second:
		return "lt_1s"
	default:
		return "gte_1s"
	}
}

type sequencerRecorder struct {
	http.ResponseWriter
	status    int
	errorCode string
}

func (recorder *sequencerRecorder) WriteHeader(status int) {
	recorder.status = status
	recorder.ResponseWriter.WriteHeader(status)
}
