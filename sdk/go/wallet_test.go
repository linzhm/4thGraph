package sdklocal

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestWalletReplay(t *testing.T) {
	fixture := os.Getenv("SCRIPT_LAB_SDK_VECTOR")
	if fixture == "" {
		t.Skip("run sdk/verify_wallet.sh PROJECT to replay the unified SDK vectors")
	}
	source, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Profile, Funding, Lock, Signed string
		ExistingOutput                 bool
		Vout                           uint32
		Recognition                    WalletRecognition
		Request                        WalletInput
		Outputs                        []Output
		Metadata                       SigningRequest
		Arguments                      []string
		Signature                      *string
	}
	if err := json.Unmarshal(source, &cases); err != nil || len(cases) == 0 {
		t.Fatalf("missing vectors: %v", err)
	}
	ctx := context.Background()
	project := os.Getenv("SCRIPT_LAB_SDK_PROJECT")
	config := Config{Bridge: os.Getenv("SCRIPT_LAB_SDK_BRIDGE"), Python: os.Getenv("SCRIPT_LAB_SDK_PYTHON")}
	for _, row := range cases {
		t.Run(row.Profile, func(t *testing.T) {
			wallet := NewWallet(project, config, row.Profile)
			prevout, err := wallet.PrevoutFromFunding(ctx, row.Funding, row.Vout)
			if err != nil || prevout != row.Request.Prevout {
				t.Fatalf("incorrect prevout: %v", err)
			}
			value := ""
			if row.Signature == nil {
				value = prevout.ValueSats
			}
			lock := row.Lock
			if !row.ExistingOutput {
				generated, err := wallet.CreateLock(ctx, LockRequest{PublicKey: row.Request.PublicKey, ValueSats: value})
				if err != nil || generated != lock {
					t.Fatalf("incorrect lock: %v", err)
				}
			}
			recognized, err := wallet.Recognize(ctx, RecognizeRequest{Script: lock, PublicKey: row.Request.PublicKey, ValueSats: value})
			if err != nil || recognized == nil || *recognized != row.Recognition {
				t.Fatalf("incorrect recognition: %v", err)
			}
			if recognized.OwnerHash160 != "" && !row.ExistingOutput {
				byOwner, err := wallet.CreateLock(ctx, LockRequest{OwnerHash160: recognized.OwnerHash160, ValueSats: value})
				if err != nil || byOwner != lock {
					t.Fatalf("incorrect owner lock: %v", err)
				}
			}
			if row.Signature == nil {
				request := Activation{Prevout: prevout, Transaction: row.Request.Transaction, InputIndex: row.Request.InputIndex,
					Sighash: row.Request.Sighash, ChronicleActive: row.Request.ChronicleActive}
				if tx, err := wallet.Activate(ctx, request); err != nil || tx != row.Signed {
					t.Fatalf("incorrect activation: %v", err)
				}
				return
			}
			calls := 0
			signer := func(request SigningRequest) ([]byte, error) {
				calls++
				args := []string{hex.EncodeToString(request.Payload)}
				if request.UserID != nil {
					args = append(args, hex.EncodeToString(request.UserID))
				}
				request.Payload, request.UserID = nil, nil
				if !reflect.DeepEqual(request, row.Metadata) || !reflect.DeepEqual(args, row.Arguments) {
					t.Fatal("incorrect signing request")
				}
				return hex.DecodeString(*row.Signature)
			}
			if tx, err := wallet.SignInput(ctx, row.Request, signer); err != nil || tx != row.Signed {
				t.Fatalf("incorrect signed input: %v", err)
			}
			request := WalletPayment{WalletSigningOptions: row.Request.WalletSigningOptions, Prevout: prevout,
				Outputs: row.Outputs, FeeSats: "100"}
			if tx, err := wallet.SignPayment(ctx, request, signer); err != nil || tx != row.Signed {
				t.Fatalf("incorrect payment: %v", err)
			}
			request.FeeSats = "99"
			if _, err := wallet.SignPayment(ctx, request, signer); err == nil || calls != 2 {
				t.Fatal("incorrect fee accepted or reached the signer")
			}
		})
	}
}
