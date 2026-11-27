package contractabi

import (
	"bytes"
	"encoding/json"
	"io"
	"unsafe"
)

const MaxPayload = 8 << 20

var input, output []byte

//go:wasmexport abi_buffer
func Buffer(length uint32) uint32 {
	if length == 0 || length > MaxPayload {
		return 0
	}
	input = make([]byte, length)
	return uint32(uintptr(unsafe.Pointer(unsafe.SliceData(input))))
}

type Project interface {
	Recognize(Request) Result
	Prepare(Request) Result
	Assemble(Request, *Prepared) Result
}

// Run binds the prepared data to a fresh recognition and preparation before assembly.
func Run(project Project, op string, length uint32) uint64 {
	r := Request{Index: -1}
	result := Fail("InvalidRequest", "invalid JSON request")
	if length == uint32(len(input)) && length > 0 {
		reader := json.NewDecoder(bytes.NewReader(input))
		reader.DisallowUnknownFields()
		if err := reader.Decode(&r); err == nil && reader.Decode(&struct{}{}) == io.EOF {
			if len(r.Prevout.Outpoint) != 36 || r.Prevout.Amount == nil || r.Prevout.Lock == nil {
				result = Fail("MissingContext", "actual prevout outpoint, amount, and lock are required")
			} else if op != "recognize" && (r.Index < 0 || len(r.Transaction.Inputs) == 0) {
				result = Fail("MissingContext", "spend requires a candidate and input index")
			} else {
				result = project.Recognize(r)
			}
			if op != "recognize" && result.Status == "Match" {
				result = project.Prepare(r)
				if op == "assemble_unlock" && result.Status == "Prepared" {
					expected, _ := json.Marshal(result.Prepared)
					supplied, _ := json.Marshal(r.Prepared)
					if !bytes.Equal(expected, supplied) {
						result = Fail("CandidateMismatch", "prepared materials differ from the bound candidate")
					} else {
						result = project.Assemble(r, result.Prepared)
					}
				}
			}
		}
	}
	output, _ = json.Marshal(result)
	return uint64(uintptr(unsafe.Pointer(unsafe.SliceData(output))))<<32 | uint64(len(output))
}

//go:wasmimport fourthgraph hash160
func hostHash160(data *byte, length uint32, out *byte)

func Hash160(data []byte) []byte {
	out := make([]byte, 20)
	hostHash160(unsafe.SliceData(data), uint32(len(data)), unsafe.SliceData(out))
	return out
}
