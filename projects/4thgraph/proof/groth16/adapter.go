// Bridges 4thGraph to the pinned Rúnar BN254 Script emitter and witness builder.
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/compiler"
	"github.com/icellan/runar/packages/runar-go/bn254witness"
)

type request struct {
	VK     string
	Public []string
	Proof  *struct {
		A []string
		B []string
		C []string
	}
}

func integers(values []string, size int) ([]*big.Int, error) {
	if len(values) != size {
		return nil, fmt.Errorf("expected %d values, got %d", size, len(values))
	}
	result := make([]*big.Int, size)
	for i, value := range values {
		n, ok := new(big.Int).SetString(value, 10)
		if !ok || n.Sign() < 0 || n.String() != value {
			return nil, fmt.Errorf("invalid decimal at index %d", i)
		}
		result[i] = n
	}
	return result, nil
}

func run() error {
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return err
	}
	pub, err := integers(req.Public, 5)
	if err != nil {
		return err
	}
	if req.Proof == nil {
		artifact, err := compiler.CompileGroth16WA(req.VK, compiler.Groth16WAOpts{PublicInputs: pub})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(artifact.Script)
	}
	vk, err := bn254witness.LoadSP1VKFromFile(req.VK)
	if err != nil {
		return err
	}
	a, err := integers(req.Proof.A, 2)
	if err != nil {
		return err
	}
	b, err := integers(req.Proof.B, 4)
	if err != nil {
		return err
	}
	c, err := integers(req.Proof.C, 2)
	if err != nil {
		return err
	}
	proof := bn254witness.Proof{A: [2]*big.Int(a), B: [4]*big.Int(b), C: [2]*big.Int(c)}
	witness, err := bn254witness.BuildFromProofWithInputs(vk, proof, pub)
	if err != nil {
		return err
	}
	encoded, err := codegen.Emit([]codegen.StackMethod{{Name: "witness", Ops: witness.ToStackOps()}})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(encoded.ScriptHex)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
