package sequencer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cirocosta/vota/internal/crypto/blind"
	"github.com/cirocosta/vota/internal/crypto/sshsig"
	"github.com/cirocosta/vota/internal/sequencerstore"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestThreePersonPollEndToEnd(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	service, keys := testService(t, now)
	members := canonicalKeys(keys)
	adminKey := canonicalKey(keys[0])
	request := CreatePollRequest{
		RequestID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)),
		Question:  "Where should we have lunch?",
		Choices:   []string{"Pizza", "Ramen", "Salad"},
		ClosesAt:  now.Add(time.Hour).Format(time.RFC3339),
		Members:   members, AdminPublicKey: adminKey,
	}
	message, err := CreatePollMessage(request)
	if err != nil {
		t.Fatal(err)
	}
	request.SSHSIG = signWithSocket(t, keys[0], adminKey, AdminNamespace, message)
	poll, created, err := service.CreatePoll(ctx, request)
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	if poll.EligibleCount != 3 || len(poll.Choices) != 3 {
		t.Fatalf("poll = %+v", poll)
	}

	receipts := make([]Receipt, len(keys))
	for index, privateKey := range keys {
		memberKey := canonicalKey(privateKey)
		issuer, err := blind.ParsePublicKey(poll.IssuerPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		serial := bytes.Repeat([]byte{byte(index + 10)}, blind.SerialSize)
		blindRequest, err := blind.Prepare(issuer, poll.PollID, poll.IssuerKeyID, serial, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		requestID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 20)}, 16))
		claimMessage, _ := ClaimMessage(poll.PollID, requestID, blindRequest.BlindedMessage)
		claim := ClaimRequest{
			SSHPublicKey: memberKey, IssuanceRequestID: requestID,
			BlindedMessage: base64.RawURLEncoding.EncodeToString(blindRequest.BlindedMessage),
			SSHSIG:         signWithSocket(t, privateKey, memberKey, CreditClaimNamespace, claimMessage),
		}
		if index == 0 {
			service.now = func() time.Time { return now.Add(2 * time.Hour) }
			if _, _, err := service.Claim(ctx, poll.PollID, claim); ErrorCode(err) != "poll_not_open" {
				t.Fatalf("expired claim error = %v", err)
			}
			service.now = func() time.Time { return now }
		}
		claimResponse, claimed, err := service.Claim(ctx, poll.PollID, claim)
		if err != nil || !claimed {
			t.Fatalf("claim %d: claimed=%v err=%v", index, claimed, err)
		}
		retried, claimed, err := service.Claim(ctx, poll.PollID, claim)
		if err != nil || claimed || retried != claimResponse {
			t.Fatalf("retry %d: claimed=%v response=%+v err=%v", index, claimed, retried, err)
		}
		if index == 0 {
			changed := append([]byte(nil), blindRequest.BlindedMessage...)
			changed[0] ^= 1
			changedMessage, _ := ClaimMessage(poll.PollID, requestID, changed)
			changedClaim := claim
			changedClaim.BlindedMessage = base64.RawURLEncoding.EncodeToString(changed)
			changedClaim.SSHSIG = signWithSocket(t, privateKey, memberKey, CreditClaimNamespace, changedMessage)
			if _, _, err := service.Claim(ctx, poll.PollID, changedClaim); ErrorCode(err) != "issuance_request_mismatch" {
				t.Fatalf("changed retry error = %v", err)
			}
		}
		blindSignature, _ := base64.RawURLEncoding.DecodeString(claimResponse.BlindSignature)
		credential, err := blind.Finalize(issuer, blindRequest.State, blindSignature)
		if err != nil {
			t.Fatal(err)
		}
		ballot := BallotRequest{Credential: Credential{
			IssuerKeyID: credential.IssuerKeyID,
			Serial:      base64.RawURLEncoding.EncodeToString(credential.Serial),
			Signature:   base64.RawURLEncoding.EncodeToString(credential.Signature),
		}, ChoiceID: poll.Choices[index].ID}
		if index == 0 {
			service.now = func() time.Time { return now.Add(2 * time.Hour) }
			if _, err := service.Vote(ctx, poll.PollID, ballot); ErrorCode(err) != "poll_not_open" {
				t.Fatalf("expired vote error = %v", err)
			}
			service.now = func() time.Time { return now }
		}
		if index == 0 {
			var concurrentReceipts [2]Receipt
			var concurrentErrors [2]error
			start := make(chan struct{})
			var wait sync.WaitGroup
			for attempt := range 2 {
				wait.Add(1)
				go func(attempt int) {
					defer wait.Done()
					<-start
					concurrentReceipts[attempt], concurrentErrors[attempt] = service.Vote(ctx, poll.PollID, ballot)
				}(attempt)
			}
			close(start)
			wait.Wait()
			codes := []string{ErrorCode(concurrentErrors[0]), ErrorCode(concurrentErrors[1])}
			slices.Sort(codes)
			if !slices.Equal(codes, []string{"credential_already_spent", "internal_error"}) {
				t.Fatalf("concurrent vote errors = %v (%v)", codes, concurrentErrors)
			}
			if concurrentErrors[0] == nil {
				receipts[index] = concurrentReceipts[0]
			} else {
				receipts[index] = concurrentReceipts[1]
			}
		} else {
			receipts[index], err = service.Vote(ctx, poll.PollID, ballot)
			if err != nil {
				t.Fatalf("vote %d: %v", index, err)
			}
		}
		if err := VerifyReceipt(service.checkpointPublic, receipts[index]); err != nil {
			t.Fatalf("receipt %d: %v", index, err)
		}
		if _, err := service.Vote(ctx, poll.PollID, ballot); ErrorCode(err) != "credential_already_spent" {
			t.Fatalf("duplicate vote error = %v", err)
		}
	}

	if _, err := service.Result(ctx, poll.PollID); ErrorCode(err) != "result_unavailable" {
		t.Fatalf("open result error = %v", err)
	}
	closeMessage, _ := ClosePollMessage(poll.PollID, adminKey)
	closeRequest := ClosePollRequest{AdminPublicKey: adminKey, SSHSIG: signWithSocket(t, keys[0], adminKey, AdminNamespace, closeMessage)}
	tally, closed, err := service.ClosePoll(ctx, poll.PollID, closeRequest)
	if err != nil || !closed || tally.BallotCount != 3 {
		t.Fatalf("close: closed=%v tally=%+v err=%v", closed, tally, err)
	}
	for _, total := range tally.Totals {
		if total.Total != 1 {
			t.Fatalf("total = %+v", total)
		}
	}
	if _, closed, err := service.ClosePoll(ctx, poll.PollID, closeRequest); err != nil || closed {
		t.Fatalf("idempotent close: closed=%v err=%v", closed, err)
	}
	bundle, err := service.Audit(ctx, poll.PollID)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAudit(bundle); err != nil {
		t.Fatal(err)
	}
	if err := service.Ready(ctx); err != nil {
		t.Fatal(err)
	}

	mutated := bundle
	mutated.Events = append([]AuditEvent(nil), bundle.Events...)
	mutated.Events[1].Artifact = append([]byte(nil), mutated.Events[1].Artifact...)
	mutated.Events[1].Artifact[0] ^= 1
	if err := VerifyAudit(mutated); err == nil {
		t.Fatal("mutated audit accepted")
	}

	removed := bundle
	removed.Events = append([]AuditEvent(nil), bundle.Events[:2]...)
	removed.Events = append(removed.Events, bundle.Events[3:]...)
	removed.Checkpoints = append([]Checkpoint(nil), bundle.Checkpoints[:2]...)
	removed.Checkpoints = append(removed.Checkpoints, bundle.Checkpoints[3:]...)
	if err := VerifyAudit(removed); err == nil {
		t.Fatal("audit with removed ballot accepted")
	}

	reordered := bundle
	reordered.Events = append([]AuditEvent(nil), bundle.Events...)
	reordered.Checkpoints = append([]Checkpoint(nil), bundle.Checkpoints...)
	reordered.Events[1], reordered.Events[2] = reordered.Events[2], reordered.Events[1]
	reordered.Checkpoints[1], reordered.Checkpoints[2] = reordered.Checkpoints[2], reordered.Checkpoints[1]
	if err := VerifyAudit(reordered); err == nil {
		t.Fatal("reordered audit accepted")
	}

	duplicated := bundle
	duplicated.Events = append([]AuditEvent(nil), bundle.Events[:2]...)
	duplicated.Events = append(duplicated.Events, bundle.Events[1:]...)
	duplicated.Checkpoints = append([]Checkpoint(nil), bundle.Checkpoints[:2]...)
	duplicated.Checkpoints = append(duplicated.Checkpoints, bundle.Checkpoints[1:]...)
	if err := VerifyAudit(duplicated); err == nil {
		t.Fatal("duplicated audit event accepted")
	}
}

func TestConcurrentClaimReturnsOneIssuance(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	service, keys := testService(t, now)
	members := canonicalKeys(keys)
	adminKey := canonicalKey(keys[0])
	create := CreatePollRequest{RequestID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)), Question: "Lunch?", Choices: []string{"A", "B"}, ClosesAt: now.Add(time.Hour).Format(time.RFC3339), Members: members, AdminPublicKey: adminKey}
	message, _ := CreatePollMessage(create)
	create.SSHSIG = signWithSocket(t, keys[0], adminKey, AdminNamespace, message)
	poll, _, err := service.CreatePoll(ctx, create)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := blind.ParsePublicKey(poll.IssuerPublicKey)
	requests := make([]ClaimRequest, 2)
	memberKey := canonicalKey(keys[1])
	for index := range requests {
		prepared, err := blind.Prepare(issuer, poll.PollID, poll.IssuerKeyID, bytes.Repeat([]byte{byte(40 + index)}, blind.SerialSize), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		requestID := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(50 + index)}, 16))
		claimMessage, _ := ClaimMessage(poll.PollID, requestID, prepared.BlindedMessage)
		requests[index] = ClaimRequest{SSHPublicKey: memberKey, IssuanceRequestID: requestID, BlindedMessage: base64.RawURLEncoding.EncodeToString(prepared.BlindedMessage), SSHSIG: signWithSocket(t, keys[1], memberKey, CreditClaimNamespace, claimMessage)}
	}
	start := make(chan struct{})
	errorsFound := make([]error, 2)
	var wait sync.WaitGroup
	for index := range requests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, _, errorsFound[index] = service.Claim(ctx, poll.PollID, requests[index])
		}(index)
	}
	close(start)
	wait.Wait()
	codes := []string{ErrorCode(errorsFound[0]), ErrorCode(errorsFound[1])}
	slices.Sort(codes)
	if !slices.Equal(codes, []string{"credit_already_claimed", "internal_error"}) {
		t.Fatalf("claim errors = %v (%v)", codes, errorsFound)
	}
}

func TestCreateValidationAndAdminAuthorization(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	service, keys := testService(t, now)
	members := canonicalKeys(keys)
	adminKey := canonicalKey(keys[0])
	request := CreatePollRequest{RequestID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)), Question: "Lunch?", Choices: []string{"Pizza", "pizza"}, ClosesAt: now.Add(time.Hour).Format(time.RFC3339), Members: members, AdminPublicKey: adminKey}
	if _, _, err := service.CreatePoll(context.Background(), request); ErrorCode(err) != "duplicate_choice" {
		t.Fatalf("duplicate choice error = %v", err)
	}

	_, outsider, _ := ed25519.GenerateKey(rand.Reader)
	request.Choices = []string{"Pizza", "Ramen"}
	request.AdminPublicKey = canonicalKey(outsider)
	if _, _, err := service.CreatePoll(context.Background(), request); ErrorCode(err) != "admin_not_authorized" {
		t.Fatalf("authorization error = %v", err)
	}

	if _, _, err := normalizeMembers([]string{members[0], members[0]}); ErrorCode(err) != "duplicate_eligible_key" {
		t.Fatalf("duplicate member error = %v", err)
	}
}

func testService(tb testing.TB, now time.Time) (*Service, []ed25519.PrivateKey) {
	tb.Helper()
	store, err := sequencerstore.Open(context.Background(), ":memory:")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	issuer, err := rsa.GenerateKey(rand.Reader, blind.MinRSAKeyBits)
	if err != nil {
		tb.Fatal(err)
	}
	_, checkpoint, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	keys := make([]ed25519.PrivateKey, 3)
	admins := make([]string, 1)
	for index := range keys {
		_, keys[index], err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			tb.Fatal(err)
		}
	}
	public, _ := ssh.NewPublicKey(keys[0].Public())
	admins[0] = string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public)))
	service, err := New(Config{Store: store, IssuerPrivateKey: issuer, CheckpointPrivateKey: checkpoint, AdminPublicKeys: admins, Now: func() time.Time { return now }})
	if err != nil {
		tb.Fatal(err)
	}
	return service, keys
}

func canonicalKeys(keys []ed25519.PrivateKey) []string {
	output := make([]string, len(keys))
	for index, privateKey := range keys {
		public, _ := ssh.NewPublicKey(privateKey.Public())
		output[index] = string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public)))
	}
	slices.Sort(output)
	return output
}

func canonicalKey(privateKey ed25519.PrivateKey) string {
	public, _ := ssh.NewPublicKey(privateKey.Public())
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(public)))
}

func signWithSocket(tb testing.TB, privateKey ed25519.PrivateKey, publicKey, namespace string, message []byte) string {
	tb.Helper()
	directory, err := os.MkdirTemp("", "vota-agent-")
	if err != nil {
		tb.Fatal(err)
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		tb.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		tb.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			_ = agent.ServeAgent(keyring, connection)
		}
	}()
	previous := os.Getenv("SSH_AUTH_SOCK")
	if err := os.Setenv("SSH_AUTH_SOCK", path); err != nil {
		tb.Fatal(err)
	}
	encoded, err := sshsig.Sign(context.Background(), []byte(publicKey), namespace, message)
	_ = os.Setenv("SSH_AUTH_SOCK", previous)
	_ = listener.Close()
	<-done
	if err != nil {
		tb.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}
