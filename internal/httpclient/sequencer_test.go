package httpclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParsePollURL(t *testing.T) {
	server, pollID, err := ParsePollURL("https://vota.example/team/polls/sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if server != "https://vota.example/team" || pollID != "sha256:abc" {
		t.Fatalf("server=%q poll=%q", server, pollID)
	}
	for _, value := range []string{"not-a-url", "https://vota.example/polls/", "https://vota.example/polls/a/b"} {
		if _, _, err := ParsePollURL(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestClientRejectsNoncanonicalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{ "poll_id": "poll" }`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SequencerPoll(context.Background(), "poll"); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("error = %v", err)
	}
}
