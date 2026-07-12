// Package auditverify provides the offline audit entry point used by the CLI.
package auditverify

import (
	"github.com/cirocosta/vota/internal/sequencer"
	"github.com/cirocosta/vota/internal/sequenceraudit"
)

func Verify(encoded []byte) (sequencer.AuditBundle, error) {
	return sequenceraudit.DecodeAndVerify(encoded)
}
