//go:build wasip1

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	abi "github.com/linzhm/4thGraph/sdk/go/contractabi"
)

// The project builder derives these values from the same compile as template.script.
var compiledPolicy string

type output struct {
	Amount uint64    `json:"satoshis"`
	Lock   abi.Bytes `json:"script_hex"`
}

type path struct {
	Mode   uint32 `json:"mode"`
	Offset int    `json:"script_code_offset"`
}

type policy struct {
	Template abi.Bytes       `json:"template_sha256"`
	Paths    map[string]path `json:"paths"`
	Contract struct {
		Locktime uint32   `json:"locktime"`
		Outputs  []output `json:"outputs"`
	} `json:"constraints"`
}

type project struct{ policy }

func load() project {
	var p policy
	raw, err := hex.DecodeString(compiledPolicy)
	if err != nil || json.Unmarshal(raw, &p) != nil {
		panic("invalid compiled settlement policy")
	}
	return project{p}
}

func (p project) Recognize(r abi.Request) abi.Result {
	if !bytes.Equal(abi.Hash(r.Prevout.Lock), p.Template) {
		return abi.Fail("NoMatch", "unknown settlement template")
	}
	return abi.Result{Status: "Match"}
}

func (p project) Prepare(r abi.Request) abi.Result {
	rule, ok := p.Paths[r.Path]
	if !ok {
		return abi.Fail("UnsupportedPath", "unknown settlement path")
	}
	tx := r.Transaction
	if r.Index != 0 || tx.Version != 2 || len(tx.Inputs) != 1 ||
		len(tx.Outputs) != len(p.Contract.Outputs) || tx.Locktime != p.Contract.Locktime {
		return abi.Fail("InvalidSuccessor", "transaction does not match the settlement shape")
	}
	remaining := *r.Prevout.Amount
	for i, want := range p.Contract.Outputs {
		out := tx.Outputs[i]
		if out.Amount > remaining || out.Amount != want.Amount || !bytes.Equal(out.Lock, want.Lock) {
			return abi.Fail("InvalidSuccessor", "ordered outputs do not satisfy the settlement")
		}
		remaining -= out.Amount
	}
	code := r.Prevout.Lock[rule.Offset:]
	prepared, err := abi.AllPreimage(r, code)
	if err != nil {
		return abi.Fail("CandidateMismatch", err.Error())
	}
	if rule.Mode == 0x61 {
		// The approved settlement has one input and short, fixed output scripts.
		// Its scriptCode is the single binding CHECKSIG.
		if !bytes.Equal(code, []byte{0xac}) || len(tx.Outputs) >= 253 {
			return abi.Fail("InvalidSuccessor", "unsupported linked settlement framing")
		}
		data := binary.LittleEndian.AppendUint32(nil, tx.Version)
		data = append(data, 1)
		data = append(data, tx.Inputs[0].Outpoint...)
		data = append(data, 1, code[0])
		data = binary.LittleEndian.AppendUint32(data, tx.Inputs[0].Sequence)
		data = append(data, byte(len(tx.Outputs)))
		for _, out := range tx.Outputs {
			if len(out.Lock) >= 253 {
				return abi.Fail("InvalidSuccessor", "unsupported output script length")
			}
			data = binary.LittleEndian.AppendUint64(data, out.Amount)
			data = append(data, byte(len(out.Lock)))
			data = append(data, out.Lock...)
		}
		data = binary.LittleEndian.AppendUint32(data, tx.Locktime)
		data = binary.LittleEndian.AppendUint32(data, rule.Mode)
		prepared.Mode, prepared.Preimage, prepared.Digest = rule.Mode, data, abi.Hash(abi.Hash(data))
	}
	return abi.Result{Status: "Prepared", Prepared: prepared}
}

func (project) Assemble(r abi.Request, p *abi.Prepared) abi.Result {
	if len(r.Authorizations) != 0 {
		return abi.Fail("InvalidAuthorization", "settlement takes no wallet signatures")
	}
	tx, in := r.Transaction, r.Transaction.Inputs[0]
	packed := binary.LittleEndian.AppendUint32(nil, tx.Version)
	packed = append(packed, in.Outpoint...)
	if p.Mode == 0x41 {
		packed = binary.LittleEndian.AppendUint64(packed, *r.Prevout.Amount)
	}
	packed = binary.LittleEndian.AppendUint32(packed, in.Sequence)
	packed = binary.LittleEndian.AppendUint32(packed, tx.Locktime)
	unlock := abi.Push(packed)
	return abi.Result{Status: "Assembled", Unlock: &unlock}
}

//go:wasmexport recognize
func recognize(n uint32) uint64 { return abi.Run(load(), "recognize", n) }

//go:wasmexport prepare_spend
func prepare(n uint32) uint64 { return abi.Run(load(), "prepare_spend", n) }

//go:wasmexport assemble_unlock
func assemble(n uint32) uint64 { return abi.Run(load(), "assemble_unlock", n) }

func main() {}
