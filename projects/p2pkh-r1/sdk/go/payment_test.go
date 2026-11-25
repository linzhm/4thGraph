package p2pkhr1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestSignPayment(t *testing.T) {
	t.Run("canonical", func(t *testing.T) { assertPayment(t, "template.hex", "spend-all.json") })
	t.Run("compiled", func(t *testing.T) { assertPayment(t, "candidates/compiled.hex", "candidates/spend-all.json") })
	t.Run("scheduled", func(t *testing.T) {
		assertPayment(t, "candidates/scheduled.hex", "candidates/scheduled-spend-all.json")
	})
}

func assertPayment(t *testing.T, templateName, vectorName string) {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("../../template/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	dec := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var v struct {
		TxID      string `json:"parent_txid"`
		Key       string `json:"public_key_x963"`
		Owner     string `json:"owner_hash160"`
		Digest    string `json:"digest_hex"`
		Preimage  string `json:"preimage_hex"`
		Signature string `json:"signature_hex"`
		Witness   string `json:"script_sig_hex"`
		SignedID  string `json:"signed_txid"`
	}
	if err := json.Unmarshal(read(vectorName), &v); err != nil {
		t.Fatal(err)
	}
	q := dec(v.Key)
	template := dec(strings.Join(strings.Fields(string(read(templateName))), ""))
	lock, err := LockForKey(template, q)
	if err != nil {
		t.Fatal(err)
	}
	p := Payment{TxID: [32]byte(dec(v.TxID)), InputScript: lock, InputSatoshis: 1000,
		Outputs: []Output{{Satoshis: 900, Script: []byte{0x51}}}, Fee: 100}
	if owner, ok := Recognize(lock); !ok || owner != [20]byte(dec(v.Owner)) {
		t.Fatal("owner recognition mismatch")
	}
	changed := bytes.Clone(lock)
	changed[228] ^= 1
	if _, ok := Recognize(changed); ok {
		t.Fatal("accepted altered template")
	}
	tx, err := SignPayment(p, q, func(d [32]byte) ([]byte, error) {
		if hex.EncodeToString(d[:]) != v.Digest {
			t.Fatal("digest differs from node vector")
		}
		return dec(v.Signature), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	messageSigned, err := SignPaymentWithMessage(p, q, func(message [32]byte) ([]byte, error) {
		if message != sha256.Sum256(dec(v.Preimage)) {
			t.Fatal("message differs from SHA256 of the node vector preimage")
		}
		return dec(v.Signature), nil
	})
	if err != nil || !bytes.Equal(messageSigned, tx) {
		t.Fatalf("message signer produced a different transaction: %v", err)
	}
	txid := hash256(tx)
	slices.Reverse(txid[:])
	if hex.EncodeToString(txid[:]) != v.SignedID || !bytes.Contains(tx, dec(v.Witness)) {
		t.Fatal("signed transaction mismatch")
	}
	if _, err = SignPayment(p, q, func([32]byte) ([]byte, error) { return make([]byte, 64), nil }); err == nil {
		t.Fatal("accepted invalid signature")
	}
	p.Fee--
	if _, err = SignPayment(p, q, func([32]byte) ([]byte, error) { t.Fatal("unexpected signer"); return nil, nil }); err == nil {
		t.Fatal("accepted wrong fee")
	}
}
