package httpapi

import (
	"io"
	"testing"
)

func TestServerDiscardsRawConnectionErrors(t *testing.T) {
	server := NewServer(ServerConfig{})
	if server.ErrorLog == nil || server.ErrorLog.Writer() != io.Discard {
		t.Fatal("server error logger can expose connection metadata")
	}
}
