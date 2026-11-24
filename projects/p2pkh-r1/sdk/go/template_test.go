package p2pkhr1

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
	read := func(name string) []byte {
		b, err := os.ReadFile("../../template/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var layout struct {
		Base string `json:"base_script_sha256"`
		Vectors []struct {
			Owner string `json:"owner_hash160"`
			Hash string `json:"script_sha256"`
			Key string `json:"public_key_x963"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(read("layout.json"), &layout); err != nil {
		t.Fatal(err)
	}
	base := decode(strings.Join(strings.Fields(string(read("template.hex"))), ""))
	for _, v := range layout.Vectors {
		owner := [20]byte(decode(v.Owner))
		script, err := LockForOwner(base, owner)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(script)
		got, ok := Recognize(script)
		if !ok || got != owner || hex.EncodeToString(digest[:]) != v.Hash {
			t.Fatal("vector mismatch", v.Owner)
		}
		if v.Key != "" {
			fromKey, err := LockForKey(base, decode(v.Key))
			if err != nil || !bytes.Equal(script, fromKey) {
				t.Fatal("public key mismatch", err)
			}
		}
	}
	hash := sha256.Sum256(base)
	if hex.EncodeToString(hash[:]) != layout.Base {
		t.Fatal("template changed")
	}
	for _, i := range []int{0, 100, 207, 228, len(base)-1} {
		mutated := bytes.Clone(base)
		mutated[i] ^= 1
		if _, ok := Recognize(mutated); ok {
			t.Fatal("accepted fixed byte change", i)
		}
		if _, err := LockForOwner(mutated, [20]byte{}); err == nil {
			t.Fatal("accepted altered template")
		}
	}
	for _, b := range [][]byte{base[1:], append(bytes.Clone(base), 0)} {
		if _, ok := Recognize(b); ok {
			t.Fatal("accepted wrong length")
		}
	}
	for _, key := range [][]byte{make([]byte, 32), append([]byte{4}, make([]byte, 64)...)} {
		if _, err := LockForKey(base, key); err == nil {
			t.Fatal("accepted malformed key")
		}
	}
}
