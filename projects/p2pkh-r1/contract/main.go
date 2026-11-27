//go:build wasip1

// Project wallet module for the reviewed ordinary v0.6.0 path.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"

	abi "github.com/linzhm/4thGraph/sdk/go/contractabi"
)

type project struct{}

const fixed = "3f1f0afba36349ab0e2ced42237ea09bf93549c20f1e7d069dee444aeadebec6"

func (project) Recognize(r abi.Request) abi.Result {
	lock := r.Prevout.Lock
	if len(lock) != 41364 || hex.EncodeToString(abi.Hash(bytes.Join([][]byte{lock[:208], lock[228:]}, nil))) != fixed {
		return abi.Fail("NoMatch", "unknown lock template")
	}
	x, _ := elliptic.Unmarshal(elliptic.P256(), r.Pubkey)
	if x == nil {
		return abi.Fail("MissingContext", "expected a local uncompressed P-256 public key")
	}
	owner := lock[208:228]
	if !bytes.Equal(abi.Hash160(r.Pubkey), owner) {
		return abi.Fail("NotOwned", "local key does not own the lock")
	}
	return abi.Result{Status: "Match", Parameters: owner}
}
func (project) Prepare(r abi.Request) abi.Result {
	if r.Path != "ordinary-all" {
		return abi.Fail("UnsupportedPath", "expected ordinary-all")
	}
	p, err := abi.AllPreimage(r, abi.Bytes{0x68, 0xac})
	if err != nil {
		return abi.Fail("CandidateMismatch", err.Error())
	}
	return abi.Result{Status: "Prepared", Prepared: p}
}
func (project) Assemble(r abi.Request, p *abi.Prepared) abi.Result {
	if len(r.Authorizations) != 1 || len(r.Authorizations[0]) != 64 {
		return abi.Fail("InvalidAuthorization", "expected raw P-256 r||s")
	}
	sig := r.Authorizations[0]
	x, y := elliptic.Unmarshal(elliptic.P256(), r.Pubkey)
	key := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	a, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key, p.Digest, a, s) {
		return abi.Fail("InvalidAuthorization", "signature differs from prepared digest")
	}
	inverse := new(big.Int).ModInverse(s, key.Curve.Params().N).FillBytes(make([]byte, 32))
	for i, j := 0, len(inverse)-1; i < j; i, j = i+1, j-1 {
		inverse[i], inverse[j] = inverse[j], inverse[i]
	}
	witness := abi.Bytes(bytes.Join([][]byte{abi.Push(p.Preimage), abi.Push(r.Pubkey), abi.Push(sig), abi.Push(inverse), {0}}, nil))
	return abi.Result{Status: "Assembled", Unlock: &witness}
}

//go:wasmexport recognize
func recognize(n uint32) uint64 { return abi.Run(project{}, "recognize", n) }

//go:wasmexport prepare_spend
func prepare(n uint32) uint64 { return abi.Run(project{}, "prepare_spend", n) }

//go:wasmexport assemble_unlock
func assemble(n uint32) uint64 { return abi.Run(project{}, "assemble_unlock", n) }

func main() {}
