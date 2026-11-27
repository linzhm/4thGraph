//go:build wasip1

// Fixed-fee full-preimage counter, using the published advance source.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	abi "github.com/linzhm/4thGraph/sdk/go/contractabi"
)

type project struct{}

const codeHash = "0ea9886c6fc34ac7915e48bef78b6869de20c6bae27c3185c78aef35a444a488"

func (project) Recognize(r abi.Request) abi.Result {
	lock := r.Prevout.Lock
	if len(lock) != 705 || lock[0] != 5 || lock[5] != 0 || lock[6] != 0xab || hex.EncodeToString(abi.Hash(lock[7:])) != codeHash {
		return abi.Fail("NoMatch", "unknown counter template")
	}
	return abi.Result{Status: "Match", Parameters: lock[1:6]}
}
func (project) Prepare(r abi.Request) abi.Result {
	if r.Path != "advance" {
		return abi.Fail("UnsupportedPath", "expected advance")
	}
	tx := r.Transaction
	amount := *r.Prevout.Amount
	if len(tx.Inputs) != 1 || len(tx.Outputs) != 1 || r.Index != 0 || amount <= 1000 || tx.Outputs[0].Amount != amount-1000 {
		return abi.Fail("InvalidSuccessor", "expected one successor and the fixed fee")
	}
	next := append(abi.Bytes(nil), r.Prevout.Lock...)
	state := binary.LittleEndian.Uint32(next[1:5])
	// uint32 addition wraps, matching the published Forth u32-inc.
	binary.LittleEndian.PutUint32(next[1:5], state+1)
	if !bytes.Equal(next, tx.Outputs[0].Lock) {
		return abi.Fail("InvalidSuccessor", "next state or code differs")
	}
	p, err := abi.AllPreimage(r, r.Prevout.Lock[7:])
	if err != nil {
		return abi.Fail("CandidateMismatch", err.Error())
	}
	return abi.Result{Status: "Prepared", Prepared: p}
}
func (project) Assemble(r abi.Request, p *abi.Prepared) abi.Result {
	if len(r.Authorizations) != 0 {
		return abi.Fail("InvalidAuthorization", "advance takes no wallet signatures")
	}
	witness := abi.Push(p.Preimage)
	return abi.Result{Status: "Assembled", Unlock: &witness}
}

//go:wasmexport recognize
func recognize(n uint32) uint64 { return abi.Run(project{}, "recognize", n) }

//go:wasmexport prepare_spend
func prepare(n uint32) uint64 { return abi.Run(project{}, "prepare_spend", n) }

//go:wasmexport assemble_unlock
func assemble(n uint32) uint64 { return abi.Run(project{}, "assemble_unlock", n) }

func main() {}
