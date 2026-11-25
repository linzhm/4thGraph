package wots

import (
	"testing"

	"github.com/linzhm/bsv-script-lab/shared/sdk/go/testkit"
)

func TestReferenceReplay(t *testing.T) {
	testkit.Replay(t, New)
}
