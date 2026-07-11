// Package httpapi exposes Vota application services over a versioned HTTP API.
package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cirocosta/vota/internal/app"
	"github.com/cirocosta/vota/internal/protocol"
)

const defaultBodyLimit = int64(protocol.MaxArtifactBytes)

type Config struct {
	Service                 *app.Service
	AdminTokenHashes        [][sha256.Size]byte
	MaxBodyBytes            int64
	VerificationConcurrency int
	RequestTimeout          time.Duration
	Ready                   func(context.Context) error
	Logger                  *slog.Logger
}

type API struct {
	service          *app.Service
	adminTokenHashes [][sha256.Size]byte
	maxBodyBytes     int64
	requestTimeout   time.Duration
	ready            func(context.Context) error
	logger           *slog.Logger
	verification     chan struct{}
	metrics          Metrics
	mux              *http.ServeMux
}

type Metrics struct {
	requests      atomic.Uint64
	errors        atomic.Uint64
	verifications atomic.Uint64
	rejectedBusy  atomic.Uint64
}

type MetricsSnapshot struct {
	Requests            uint64 `json:"http_requests_total"`
	Errors              uint64 `json:"http_errors_total"`
	ActiveVerifications uint64 `json:"verification_active"`
	RejectedBusy        uint64 `json:"verification_rejected_total"`
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func New(config Config) (*API, error) {
	if config.Service == nil {
		return nil, errors.New("nil application service")
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = defaultBodyLimit
	}
	if config.VerificationConcurrency <= 0 {
		config.VerificationConcurrency = 4
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 15 * time.Second
	}
	if config.Ready == nil {
		config.Ready = config.Service.Ready
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	api := &API{
		service:          config.Service,
		adminTokenHashes: append([][sha256.Size]byte(nil), config.AdminTokenHashes...),
		maxBodyBytes:     config.MaxBodyBytes,
		requestTimeout:   config.RequestTimeout,
		ready:            config.Ready,
		logger:           config.Logger,
		verification:     make(chan struct{}, config.VerificationConcurrency),
		mux:              http.NewServeMux(),
	}
	api.routes()
	return api, nil
}

func HashAdminToken(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

func (api *API) Metrics() MetricsSnapshot {
	return MetricsSnapshot{
		Requests:            api.metrics.requests.Load(),
		Errors:              api.metrics.errors.Load(),
		ActiveVerifications: api.metrics.verifications.Load(),
		RejectedBusy:        api.metrics.rejectedBusy.Load(),
	}
}

func (api *API) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	started := time.Now()
	requestID := newRequestID()
	ctx, cancel := context.WithTimeout(request.Context(), api.requestTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, requestIDKey{}, requestID)
	request = request.WithContext(ctx)
	recorder := &statusRecorder{ResponseWriter: response, status: http.StatusOK}
	api.metrics.requests.Add(1)
	api.mux.ServeHTTP(recorder, request)
	if recorder.status >= 400 {
		api.metrics.errors.Add(1)
	}
	api.logger.InfoContext(ctx, "http request",
		"request_id", requestID,
		"method", request.Method,
		"route", request.Pattern,
		"status", recorder.status,
		"duration_ms", time.Since(started).Milliseconds(),
	)
}

func (api *API) routes() {
	api.mux.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		api.writeError(response, http.StatusNotFound, "not_found", requestID(request))
	})
	api.mux.HandleFunc("GET /healthz", api.health)
	api.mux.HandleFunc("GET /readyz", api.readiness)
	api.mux.HandleFunc("POST /v1/polls", api.publishPoll)
	api.mux.HandleFunc("GET /v1/polls/{poll_id}", api.getPoll)
	api.mux.HandleFunc("POST /v1/polls/{poll_id}/ballots", api.submitBallot)
	api.mux.HandleFunc("GET /v1/polls/{poll_id}/receipts/{ballot_hash}", api.getReceipt)
	api.mux.HandleFunc("POST /v1/polls/{poll_id}/close", api.closePoll)
	api.mux.HandleFunc("POST /v1/polls/{poll_id}/tally-shares", api.submitShare)
	api.mux.HandleFunc("GET /v1/polls/{poll_id}/tally", api.getTally)
	api.mux.HandleFunc("GET /v1/polls/{poll_id}/audit", api.getAudit)
}

func (api *API) health(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (api *API) readiness(response http.ResponseWriter, request *http.Request) {
	if err := api.ready(request.Context()); err != nil {
		api.writeError(response, http.StatusServiceUnavailable, "not_ready", requestID(request))
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
}

func (api *API) publishPoll(response http.ResponseWriter, request *http.Request) {
	if !api.authorized(request) {
		api.writeError(response, http.StatusUnauthorized, "unauthorized", requestID(request))
		return
	}
	body, ok := api.readJSONBody(response, request)
	if !ok {
		return
	}
	value, created, err := api.service.PublishPoll(request.Context(), body)
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(response, status, value)
}

func (api *API) getPoll(response http.ResponseWriter, request *http.Request) {
	status, err := api.service.PollStatus(request.Context(), request.PathValue("poll_id"))
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (api *API) submitBallot(response http.ResponseWriter, request *http.Request) {
	if !api.acquireVerification(response, request) {
		return
	}
	defer api.releaseVerification()
	body, ok := api.readJSONBody(response, request)
	if !ok {
		return
	}
	var ballot protocol.BallotEnvelope
	if !decodeCanonical(response, request, body, &ballot, api) {
		return
	}
	if ballot.PollID != request.PathValue("poll_id") {
		api.writeError(response, http.StatusUnprocessableEntity, "wrong_poll", requestID(request))
		return
	}
	receipt, created, err := api.service.AcceptBallot(request.Context(), ballot)
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(response, status, receipt)
}

func (api *API) getReceipt(response http.ResponseWriter, request *http.Request) {
	receipt, err := api.service.Receipt(request.Context(), request.PathValue("poll_id"), request.PathValue("ballot_hash"))
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, receipt)
}

func (api *API) closePoll(response http.ResponseWriter, request *http.Request) {
	if !api.authorized(request) {
		api.writeError(response, http.StatusUnauthorized, "unauthorized", requestID(request))
		return
	}
	aggregate, _, err := api.service.ClosePoll(request.Context(), request.PathValue("poll_id"))
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, aggregate)
}

func (api *API) submitShare(response http.ResponseWriter, request *http.Request) {
	if !api.acquireVerification(response, request) {
		return
	}
	defer api.releaseVerification()
	body, ok := api.readJSONBody(response, request)
	if !ok {
		return
	}
	var share protocol.TrusteeShare
	if !decodeCanonical(response, request, body, &share, api) {
		return
	}
	if share.PollID != request.PathValue("poll_id") {
		api.writeError(response, http.StatusUnprocessableEntity, "wrong_poll", requestID(request))
		return
	}
	tally, created, err := api.service.SubmitTrusteeShare(request.Context(), share)
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(response, status, map[string]any{"tally": tally})
}

func (api *API) getTally(response http.ResponseWriter, request *http.Request) {
	tally, err := api.service.Tally(request.Context(), request.PathValue("poll_id"))
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, tally)
}

func (api *API) getAudit(response http.ResponseWriter, request *http.Request) {
	bundle, err := api.service.ExportAudit(request.Context(), request.PathValue("poll_id"))
	if err != nil {
		api.writeAppError(response, request, err)
		return
	}
	response.Header().Set("Content-Type", "application/gzip")
	response.Header().Set("Content-Encoding", "gzip")
	response.WriteHeader(http.StatusOK)
	writer := gzip.NewWriter(response)
	_, _ = writer.Write(bundle)
	_ = writer.Close()
}

func (api *API) readJSONBody(response http.ResponseWriter, request *http.Request) ([]byte, bool) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		api.writeError(response, http.StatusUnsupportedMediaType, "unsupported_content_type", requestID(request))
		return nil, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, api.maxBodyBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			api.writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", requestID(request))
		} else {
			api.writeError(response, http.StatusBadRequest, "invalid_request_body", requestID(request))
		}
		return nil, false
	}
	return body, true
}

func (api *API) authorized(request *http.Request) bool {
	scheme, token, ok := strings.Cut(request.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	matched := 0
	for _, expected := range api.adminTokenHashes {
		matched |= subtle.ConstantTimeCompare(digest[:], expected[:])
	}
	return matched == 1
}

func (api *API) acquireVerification(response http.ResponseWriter, request *http.Request) bool {
	select {
	case api.verification <- struct{}{}:
		api.metrics.verifications.Add(1)
		return true
	default:
		api.metrics.rejectedBusy.Add(1)
		api.writeError(response, http.StatusServiceUnavailable, "verification_busy", requestID(request))
		return false
	}
}

func (api *API) releaseVerification() {
	<-api.verification
	api.metrics.verifications.Add(^uint64(0))
}

func decodeCanonical(response http.ResponseWriter, request *http.Request, body []byte, target any, api *API) bool {
	if err := protocol.DecodeStrict(body, target); err != nil {
		api.writeError(response, http.StatusUnprocessableEntity, "invalid_json", requestID(request))
		return false
	}
	canonical, err := protocol.MarshalCanonical(target)
	if err != nil || !bytes.Equal(body, canonical) {
		api.writeError(response, http.StatusUnprocessableEntity, "noncanonical_json", requestID(request))
		return false
	}
	return true
}

func (api *API) writeAppError(response http.ResponseWriter, request *http.Request, err error) {
	code := app.ErrorCode(err)
	api.writeError(response, statusFor(code), code, requestID(request))
}

func (api *API) writeError(response http.ResponseWriter, status int, code, id string) {
	writeJSON(response, status, errorEnvelope{Error: errorBody{Code: code, Message: publicMessage(code), RequestID: id}})
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

func statusFor(code string) int {
	switch code {
	case "poll_not_found", "ballot_not_found", "tally_unavailable":
		return http.StatusNotFound
	case "double_vote", "poll_closed", "poll_conflict", "ballot_conflict", "tally_final", "duplicate_trustee_share", "privacy_threshold_not_met":
		return http.StatusConflict
	case "poll_not_open", "no_accepted_ballots":
		return http.StatusUnprocessableEntity
	default:
		if strings.HasPrefix(code, "invalid_") || strings.HasPrefix(code, "wrong_") || strings.HasPrefix(code, "noncanonical_") || strings.Contains(code, "mismatch") || strings.HasPrefix(code, "unsupported_") {
			return http.StatusUnprocessableEntity
		}
		return http.StatusInternalServerError
	}
}

func publicMessage(code string) string {
	messages := map[string]string{
		"unauthorized":              "valid administrator authentication is required",
		"double_vote":               "an accepted ballot already uses this poll nullifier",
		"poll_closed":               "the poll is closed",
		"poll_not_open":             "the poll is not open",
		"poll_not_found":            "the poll was not found",
		"ballot_not_found":          "the receipt was not found",
		"tally_unavailable":         "the tally is not available",
		"privacy_threshold_not_met": "the privacy threshold was not met",
		"verification_busy":         "proof verification capacity is busy",
		"request_too_large":         "the request body exceeds the configured limit",
		"unsupported_content_type":  "content type must be application/json",
		"invalid_json":              "the JSON artifact is invalid",
		"noncanonical_json":         "the JSON artifact is not canonical",
	}
	if message, ok := messages[code]; ok {
		return message
	}
	if statusFor(code) >= 500 {
		return "internal server error"
	}
	return strings.ReplaceAll(code, "_", " ")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	recorder.status = status
	recorder.ResponseWriter.WriteHeader(status)
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
