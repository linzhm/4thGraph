package deferred

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPublicVectors(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	decode := func(value string) []byte {
		b, err := hex.DecodeString(strings.Join(strings.Fields(value), ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var layout struct {
		Vectors []struct {
			ID         int    `json:"id"`
			Satoshis   int64  `json:"value_sats"`
			PublicKey  string `json:"public_key_x963"`
			OwnerHash  string `json:"owner_hash160"`
			ScriptHash string `json:"target_script_sha256"`
			OutputHash string `json:"target_txout_hash256"`
			LockHash   string `json:"locking_script_sha256"`
			LegacyHash string `json:"legacy_locking_script_sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal([]byte(read("../../template/layout.json")), &layout); err != nil {
		t.Fatal(err)
	}
	var activation struct {
		VectorID int    `json:"vector_id"`
		Preimage string `json:"activation_preimage_hex"`
		Witness  string `json:"unlocking_script_hex"`
	}
	if err := json.Unmarshal([]byte(read("../../template/activation-single.json")), &activation); err != nil {
		t.Fatal(err)
	}
	var modes struct {
		Cases []struct {
			Sighash   string `json:"sighash"`
			Preimage  string `json:"activation_preimage_hex"`
			Auxiliary string `json:"auxiliary_hex"`
			Witness   string `json:"unlocking_script_hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal([]byte(read("../../template/sighash-modes.json")), &modes); err != nil {
		t.Fatal(err)
	}
	template := decode(read("../../template/template.hex"))
	r1 := decode(read("../../../p2pkh-r1/template/template.hex"))
	for _, vector := range layout.Vectors {
		script, err := LockForKey(template, r1, decode(vector.PublicKey), vector.Satoshis)
		if err != nil || sha256.Sum256(script) != [32]byte(decode(vector.LockHash)) {
			t.Fatalf("generation vector %d failed: %v", vector.ID, err)
		}
		owner := [20]byte(decode(vector.OwnerHash))
		byOwner, err := LockForOwner(template, r1, owner, vector.Satoshis)
		if err != nil || !bytes.Equal(byOwner, script) {
			t.Fatalf("generation from owner hash %d failed: %v", vector.ID, err)
		}
		recognized, ok := Recognize(r1, script, vector.Satoshis)
		if !ok || recognized != (Commitment{OwnerHash160: owner, TargetScriptSHA256: [32]byte(decode(vector.ScriptHash)),
			TargetTxOutHash256: [32]byte(decode(vector.OutputHash))}) {
			t.Fatalf("recognition vector %d failed", vector.ID)
		}
		legacy := append(append([]byte{65}, decode(vector.PublicKey)...), script[21:]...)
		if sha256.Sum256(legacy) != [32]byte(decode(vector.LegacyHash)) {
			t.Fatalf("legacy generation vector %d failed", vector.ID)
		}
		wantLegacy := recognized
		wantLegacy.PublicKey = [65]byte(decode(vector.PublicKey))
		if result, ok := Recognize(r1, legacy, vector.Satoshis); !ok || result != wantLegacy {
			t.Fatalf("legacy recognition vector %d failed", vector.ID)
		}
		if _, ok := Recognize(r1, script, vector.Satoshis+1); ok {
			t.Fatal("recognized a different amount")
		}
		if vector.ID == activation.VectorID {
			preimage := decode(activation.Preimage)
			witness, err := ActivationWitness(r1, script, vector.Satoshis, preimage)
			if err != nil || hex.EncodeToString(witness) != activation.Witness {
				t.Fatalf("activation vector failed: %v", err)
			}
			preimage[118] ^= 1
			if _, err := ActivationWitness(r1, script, vector.Satoshis, preimage); err == nil {
				t.Fatal("accepted a different target hash")
			}
			for _, mode := range modes.Cases {
				paired := decode(mode.Preimage)
				var additional [][]byte
				if mode.Auxiliary != "" {
					additional = append(additional, decode(mode.Auxiliary))
				}
				witness, err := ActivationWitness(r1, script, vector.Satoshis, paired, additional...)
				if err != nil || hex.EncodeToString(witness) != mode.Witness {
					t.Fatalf("activation mode %s failed: %v", mode.Sighash, err)
				}
				if len(additional) != 0 {
					additional[0][0] ^= 0x80
					if _, err := ActivationWitness(r1, script, vector.Satoshis, paired, additional...); err == nil {
						t.Fatal("accepted a different ANYONECANPAY bit")
					}
				}
			}
		}
	}
}
