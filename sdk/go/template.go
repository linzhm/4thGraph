// Package p2pkhr1 constructs and identifies canonical P2PKH-R1 scriptPubKeys.
package p2pkhr1

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"

	"golang.org/x/crypto/ripemd160"
)

const size, start, end = 59582, 208, 228
const fingerprint = "2129d374594069d08a9b2127555f48ea21c75fb06d1ad5e77c68ad251e97f784"

var header = regexp.MustCompile("^760052a569766b7c8201[0-9a-f]{396}([0-9a-f]{40})$")

// Recognize accepts raw script bytes starting at the first opcode.
func Recognize(script []byte) ([20]byte, bool) {
	var owner [20]byte
	if len(script) != size {
		return owner, false
	}
	match := header.FindStringSubmatch(hex.EncodeToString(script[:end]))
	if match == nil {
		return owner, false
	}
	h := sha256.New()
	h.Write(script[:start])
	h.Write(script[end:])
	if hex.EncodeToString(h.Sum(nil)) != fingerprint {
		return owner, false
	}
	hex.Decode(owner[:], []byte(match[1]))
	return owner, true
}

func LockForOwner(template []byte, owner [20]byte) ([]byte, error) {
	if _, ok := Recognize(template); !ok {
		return nil, errors.New("unrecognized P2PKH-R1 template")
	}
	script := append([]byte(nil), template...)
	copy(script[start:end], owner[:])
	return script, nil
}

func LockForKey(template, key []byte) ([]byte, error) {
	if len(key) != 65 || key[0] != 4 {
		return nil, errors.New("expected uncompressed P-256 public key")
	}
	if _, err := ecdh.P256().NewPublicKey(key); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(key)
	h := ripemd160.New()
	h.Write(digest[:])
	var owner [20]byte
	copy(owner[:], h.Sum(nil))
	return LockForOwner(template, owner)
}
