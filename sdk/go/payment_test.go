package p2pkhr1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestSignPayment(t *testing.T) {
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
		TxID string `json:"parent_txid"`
		Key string `json:"public_key_x963"`
		Digest string `json:"digest_hex"`
		Signature string `json:"signature_hex"`
		Witness string `json:"script_sig_hex"`
		SignedID string `json:"signed_txid"`
	}
	if err := json.Unmarshal(read("spend-all.json"), &v); err != nil {
		t.Fatal(err)
	}
	q := dec(v.Key)
	template := dec(strings.Join(strings.Fields(string(read("template.hex"))), ""))
	lock, err := LockForKey(template, q)
	if err != nil {
		t.Fatal(err)
	}
	p := Payment{TxID: [32]byte(dec(v.TxID)), InputScript: lock, InputSatoshis: 1000,
		Outputs: []Output{{Satoshis: 900, Script: []byte{0x51}}}, Fee: 100}
	tx, err := SignPayment(p, q, func(d [32]byte) ([]byte, error) {
		if hex.EncodeToString(d[:]) != v.Digest {
			t.Fatal("digest differs from node vector")
		}
		return dec(v.Signature), nil
	})
	if err != nil {
		t.Fatal(err)
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
