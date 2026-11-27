// Package contractabi contains the version-one wire types for project contract modules.
package contractabi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type Bytes []byte

func (b Bytes) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(b)), nil }
func (b *Bytes) UnmarshalText(text []byte) error {
	raw, err := hex.DecodeString(string(text))
	*b = raw
	return err
}

type Output struct {
	Amount uint64 `json:"amount"`
	Lock   Bytes  `json:"lock"`
}
type Prevout struct {
	Outpoint Bytes   `json:"outpoint"`
	Amount   *uint64 `json:"amount"`
	Lock     Bytes   `json:"lock"`
}
type Input struct {
	Outpoint Bytes  `json:"outpoint"`
	Script   Bytes  `json:"script"`
	Sequence uint32 `json:"sequence"`
}
type Tx struct {
	Version  uint32   `json:"version"`
	Inputs   []Input  `json:"inputs"`
	Outputs  []Output `json:"outputs"`
	Locktime uint32   `json:"locktime"`
}
type Request struct {
	Prevout        Prevout   `json:"prevout"`
	Pubkey         Bytes     `json:"pubkey"`
	Transaction    Tx        `json:"transaction"`
	Index          int       `json:"input_index"`
	Path           string    `json:"path"`
	Prepared       *Prepared `json:"prepared,omitempty"`
	Authorizations []Bytes   `json:"authorizations,omitempty"`
}
type Prepared struct {
	Candidate Bytes  `json:"candidate"`
	Outpoint  Bytes  `json:"outpoint"`
	Index     int    `json:"input_index"`
	Path      string `json:"path"`
	Mode      uint32 `json:"mode"`
	Preimage  Bytes  `json:"preimage"`
	Digest    Bytes  `json:"digest"`
}
type Result struct {
	Status     string    `json:"status"`
	Detail     string    `json:"detail,omitempty"`
	Parameters Bytes     `json:"parameters,omitempty"`
	Prepared   *Prepared `json:"prepared,omitempty"`
	Unlock     *Bytes    `json:"unlock,omitempty"`
}

func Fail(status, detail string) Result { return Result{Status: status, Detail: detail} }

func le32(x uint32) []byte { return binary.LittleEndian.AppendUint32(nil, x) }
func le64(x uint64) []byte { return binary.LittleEndian.AppendUint64(nil, x) }
func compact(n int) []byte {
	switch {
	case n < 253:
		return []byte{byte(n)}
	case n <= 65535:
		return binary.LittleEndian.AppendUint16([]byte{253}, uint16(n))
	default:
		return binary.LittleEndian.AppendUint32([]byte{254}, uint32(n))
	}
}
func blob(b []byte) []byte      { return append(compact(len(b)), b...) }
func Hash(data []byte) Bytes    { h := sha256.Sum256(data); return h[:] }
func hash256(data []byte) Bytes { return Hash(Hash(data)) }
func Push(data []byte) Bytes {
	var prefix []byte
	switch {
	case len(data) < 76:
		prefix = []byte{byte(len(data))}
	case len(data) < 256:
		prefix = []byte{76, byte(len(data))}
	case len(data) < 65536:
		prefix = binary.LittleEndian.AppendUint16([]byte{77}, uint16(len(data)))
	default:
		prefix = binary.LittleEndian.AppendUint32([]byte{78}, uint32(len(data)))
	}
	return append(prefix, data...)
}

// AllPreimage produces ordinary ForkID ALL using the project's path-specific scriptCode.
func AllPreimage(r Request, code Bytes) (*Prepared, error) {
	t := r.Transaction
	if r.Prevout.Amount == nil {
		return nil, fmt.Errorf("prevout amount is required")
	}
	amount := *r.Prevout.Amount
	if r.Index < 0 || r.Index >= len(t.Inputs) || !bytes.Equal(t.Inputs[r.Index].Outpoint, r.Prevout.Outpoint) ||
		amount > 2100000000000000 || len(t.Inputs[r.Index].Script) != 0 {
		return nil, fmt.Errorf("input does not spend this prevout or already has a witness")
	}
	raw := append(le32(t.Version), compact(len(t.Inputs))...)
	var outpoints, sequences, outputs []byte
	for _, in := range t.Inputs {
		if len(in.Outpoint) != 36 {
			return nil, fmt.Errorf("expected a 36-byte wire outpoint")
		}
		outpoints = append(outpoints, in.Outpoint...)
		sequences = append(sequences, le32(in.Sequence)...)
		raw = append(raw, in.Outpoint...)
		raw = append(raw, blob(in.Script)...)
		raw = append(raw, le32(in.Sequence)...)
	}
	for _, out := range t.Outputs {
		if out.Amount > 2100000000000000 {
			return nil, fmt.Errorf("output amount exceeds money range")
		}
		outputs = append(outputs, le64(out.Amount)...)
		outputs = append(outputs, blob(out.Lock)...)
	}
	raw = append(raw, compact(len(t.Outputs))...)
	raw = append(raw, outputs...)
	raw = append(raw, le32(t.Locktime)...)
	pre := bytes.Join([][]byte{le32(t.Version), hash256(outpoints), hash256(sequences), r.Prevout.Outpoint,
		blob(code), le64(amount), le32(t.Inputs[r.Index].Sequence), hash256(outputs), le32(t.Locktime), le32(0x41)}, nil)
	return &Prepared{Hash(raw), r.Prevout.Outpoint, r.Index, r.Path, 0x41, pre, hash256(pre)}, nil
}
