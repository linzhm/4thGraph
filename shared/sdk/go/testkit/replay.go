// Package testkit replays the public Script Lab integration fixtures.
package testkit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	sdk "github.com/linzhm/bsv-script-lab/shared/sdk/go"
)

type vector struct {
	Profile     string
	Lock        string
	Recognition sdk.Recognition
	Request     sdk.Spend
	Outputs     []sdk.Output
	Arguments   []string
	Signature   string
	Signed      string
}

func Replay(t *testing.T, newClient func(sdk.Config) *sdk.Client) {
	t.Helper()
	fixture := os.Getenv("SCRIPT_LAB_SDK_VECTOR")
	if fixture == "" {
		t.Skip("generate a public integration vector with shared/sdk/tests/vector.py")
	}
	source, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(source, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("missing integration cases")
	}
	configuration := sdk.Config{Bridge: os.Getenv("SCRIPT_LAB_SDK_BRIDGE"), Python: os.Getenv("SCRIPT_LAB_SDK_PYTHON")}
	client := newClient(configuration)
	ctx := context.Background()
	for _, row := range vectors {
		t.Run(row.Profile, func(t *testing.T) {
			publicKey := row.Request.PublicKey
			lock, err := client.Lock(ctx, publicKey, row.Profile)
			if err != nil || lock != row.Lock {
				t.Fatalf("locking script mismatch: %v", err)
			}
			recognized, err := client.Recognize(ctx, lock, publicKey)
			if err != nil || recognized == nil || *recognized != row.Recognition {
				t.Fatalf("template mismatch: %v", err)
			}
			if recognized.OwnerHash160 != "" {
				byOwner, err := client.LockForOwner(ctx, recognized.OwnerHash160)
				if err != nil || byOwner != lock {
					t.Fatalf("locking script from owner hash: %v", err)
				}
			}
			if recognized, err := client.Recognize(ctx, "00"+lock[2:], publicKey); err != nil || recognized != nil {
				t.Fatalf("malformed locking script result: %v", err)
			}
			calls := 0
			signer := func(arguments ...[]byte) ([]byte, error) {
				calls++
				actual := make([]string, len(arguments))
				for i, arg := range arguments {
					actual[i] = hex.EncodeToString(arg)
				}
				if !reflect.DeepEqual(actual, row.Arguments) {
					t.Fatal("signer arguments differ from reference")
				}
				return hex.DecodeString(row.Signature)
			}
			payment := sdk.Payment{SigningOptions: row.Request.SigningOptions, FeeSats: "100", Outputs: row.Outputs}
			if tx, err := client.SignSpend(ctx, row.Request, signer); err != nil || tx != row.Signed {
				t.Fatalf("prepared spend mismatch: %v", err)
			}
			if tx, err := client.SignPayment(ctx, payment, signer); err != nil || tx != row.Signed {
				t.Fatalf("payment mismatch: %v", err)
			}
			payment.FeeSats = "99"
			if _, err := client.SignPayment(ctx, payment, signer); err == nil || calls != 2 {
				t.Fatal("invalid fee reached the signer or did not fail")
			}
			if _, err := client.SignSpend(ctx, row.Request, func(...[]byte) ([]byte, error) {
				return []byte{0}, nil
			}); err == nil {
				t.Fatal("invalid signature was accepted")
			}
		})
	}
}
