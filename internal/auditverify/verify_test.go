package auditverify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyFixture(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "sequenceraudit", "testdata", "closed-poll.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(encoded); err != nil {
		t.Fatal(err)
	}
}
