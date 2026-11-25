package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/linzhm/BSV-Script-Lab/projects/spv-token/recursion/keycommit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	backendWitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	blsConstraint "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	frontendcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
)

type provingState struct {
	ccs       constraint.ConstraintSystem
	pad       padding
	vk        *native.VerifyingKey
	pk        groth16.ProvingKey
	key       keycommit.Key
	artifact  keyArtifact
	keyDigest [32]byte
}

type issuedProof struct {
	proof  Proof
	digest [32]byte
}

var progress io.Writer = os.Stdout

func compile() (*provingState, *native.VerifyingKey, error) {
	pad, padKey, err := loadPadding()
	if err != nil {
		return nil, nil, fmt.Errorf("padding proof: %w", err)
	}
	start := time.Now()
	ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, circuitTemplate(pad))
	if err != nil {
		return nil, nil, fmt.Errorf("compile continuity circuit: %w", err)
	}
	commits := ccs.GetCommitments().(constraint.Groth16Commitments)
	if len(commits) != 1 || len(commits[0].GetPublicCommitted()) != 0 {
		return nil, nil, fmt.Errorf("unexpected BSB22 layout")
	}
	fmt.Fprintf(progress, "compiled %d continuity constraints in %v\n", ccs.GetNbConstraints(), time.Since(start))
	return &provingState{ccs: ccs, pad: pad}, padKey, nil
}

func (s *provingState) useKey(vk *native.VerifyingKey) error {
	var err error
	s.vk = vk
	s.key, err = recursive.ValueOfVerifyingKey[G1, G2, GT](vk)
	if err != nil {
		return err
	}
	s.keyDigest, err = keycommit.Digest(vk)
	if err != nil {
		return err
	}
	s.artifact, err = encodeKey(vk)
	return err
}

func (s *provingState) makeWitness(t Transcript, priors ...issuedProof) *Circuit {
	w := &Circuit{Count: t.Count, Key: s.key, Proofs: [2]Proof{s.pad.Proof, s.pad.Proof}}
	applyTranscript(w, t)
	for i, prior := range priors {
		w.Proofs[i] = prior.proof
	}
	return w
}

func applyTranscript(w *Circuit, t Transcript) {
	public := limbs(t.Digest())
	w.Digest, w.Count = [2]frontend.Variable{public[0], public[1]}, t.Count
	for i := range t.Asset {
		w.Asset[i], w.SelfID[i], w.Context[i] = t.Asset[i], t.SelfKey[i], t.Context[i]
		w.Prior[0][i], w.Prior[1][i] = t.Prior[0][i], t.Prior[1][i]
	}
}

func (s *provingState) transcript(asset, context [32]byte, priors ...issuedProof) Transcript {
	t := Transcript{Asset: asset, SelfKey: s.keyDigest, Context: context, Count: uint8(len(priors))}
	for i, prior := range priors {
		t.Prior[i] = prior.digest
	}
	return t
}

func (s *provingState) prove(label, path string, t Transcript, priors ...issuedProof) (issuedProof, error) {
	w, err := frontend.NewWitness(s.makeWitness(t, priors...), fr.Modulus())
	if err != nil {
		return issuedProof{}, err
	}
	start := time.Now()
	proof, err := groth16.Prove(s.ccs, s.pk, w, recursive.GetNativeProverOptions(fr.Modulus(), fr.Modulus()))
	if err != nil {
		return issuedProof{}, fmt.Errorf("%s prove: %w", label, err)
	}
	proofNative, digest := proof.(*native.Proof), t.Digest()
	if err = nativeVerify(s.vk, proofNative, digest); err != nil {
		return issuedProof{}, fmt.Errorf("%s verify: %w", label, err)
	}
	if err = writeJSON(path, encodeProof(s.artifact, proofNative, t)); err != nil {
		return issuedProof{}, err
	}
	typed, err := recursive.ValueOfProof[G1, G2](proof)
	if err != nil {
		return issuedProof{}, err
	}
	fmt.Fprintf(progress, "%s: arity %d verified in %v, proof %s\n", label, t.Count, time.Since(start), path)
	return issuedProof{typed, digest}, nil
}

func solverWitness(c frontend.Circuit) (backendWitness.Witness, solver.Option, error) {
	w, err := frontend.NewWitness(c, fr.Modulus())
	challenge := solver.OverrideHint(solver.GetHintID(frontendcs.Bsb22CommitmentComputePlaceholder),
		func(mod *big.Int, _ []*big.Int, out []*big.Int) error {
			v, err := rand.Int(rand.Reader, mod)
			if err == nil {
				out[0].Set(v)
			}
			return err
		})
	return w, challenge, err
}

func (s *provingState) solve(label string, c *Circuit, valid bool) error {
	w, challenge, err := solverWitness(c)
	if err != nil {
		return err
	}
	_, err = s.ccs.Solve(w, challenge)
	if valid {
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		fmt.Printf("solved %s\n", label)
		return nil
	}
	var invalid *blsConstraint.UnsatisfiedConstraintError
	if !errors.As(err, &invalid) {
		return fmt.Errorf("%s failed to reject at a constraint: %v", label, err)
	}
	fmt.Printf("rejected %s\n", label)
	return nil
}

func (s *provingState) demo(directory string) error {
	asset := sha256.Sum256([]byte("CCTP continuity demonstration asset"))
	mintContext := sha256.Sum256([]byte("base context A (Script validates the actual mint)"))
	mintOther := sha256.Sum256([]byte("base context B (Script validates the actual mint)"))
	mergeContext := sha256.Sum256([]byte("recursive context"))
	nextContext := sha256.Sum256([]byte("next recursive context"))
	base := s.transcript(asset, mintContext)
	a, err := s.prove("base A", filepath.Join(directory, "base-a.json"), base)
	if err != nil {
		return err
	}
	b, err := s.prove("base B", filepath.Join(directory, "base-b.json"), s.transcript(asset, mintOther))
	if err != nil {
		return err
	}
	merge := s.transcript(asset, mergeContext, a, b)
	m, err := s.prove("base A + base B", filepath.Join(directory, "recursive-one.json"), merge, a, b)
	if err != nil {
		return err
	}
	if _, err = s.prove("child of recursive proof", filepath.Join(directory, "recursive-two.json"), s.transcript(asset, nextContext, m), m); err != nil {
		return err
	}

	badPrior := s.makeWitness(merge, b, a)
	foreignKey := s.makeWitness(base)
	foreignKey.Key = s.pad.Key
	badArity := base
	badArity.Count = 3
	unused := base
	unused.Prior[1] = b.digest
	for _, negative := range []struct {
		label   string
		witness *Circuit
	}{
		{"prior proof under incorrect ordered digest", badPrior},
		{"padding key as the declared self key", foreignKey},
		{"three active predecessors", s.makeWitness(badArity)},
		{"nonzero inactive digest", s.makeWitness(unused)},
	} {
		if err := s.solve(negative.label, negative.witness, false); err != nil {
			return err
		}
	}
	return s.solve("one digest referenced by two distinct Script outpoints", s.makeWitness(s.transcript(asset, nextContext, m, m), m, m), true)
}

func writeKey(path string, key io.WriterTo) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(file, 1<<20)
	_, err = key.WriteTo(w)
	if err == nil {
		err = w.Flush()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func readKey(path string, key io.ReaderFrom) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = key.ReadFrom(bufio.NewReaderSize(file, 1<<20))
	return err
}

func (s *provingState) fingerprint() (string, error) {
	h := sha256.New()
	if _, err := s.ccs.WriteTo(h); err != nil {
		return "", err
	}
	return "cctp-continuity/v1 " + hex.EncodeToString(h.Sum(nil)) + "\n", nil
}

func (s *provingState) saveKeys(directory string) error {
	fingerprint, err := s.fingerprint()
	if err != nil {
		return err
	}
	if err = writeKey(filepath.Join(directory, "proving.key"), s.pk); err != nil {
		return err
	}
	if err = writeKey(filepath.Join(directory, "verifying.key"), s.vk); err != nil {
		return err
	}
	manifest := filepath.Join(directory, ".circuit-pending")
	if err := os.WriteFile(manifest, []byte(fingerprint), 0600); err != nil {
		return err
	}
	return os.Rename(manifest, filepath.Join(directory, "circuit.txt"))
}

func (s *provingState) loadKeys(directory string) error {
	fingerprint, err := s.fingerprint()
	if err != nil {
		return err
	}
	cache, err := os.ReadFile(filepath.Join(directory, "circuit.txt"))
	if err != nil {
		return err
	}
	if string(cache) != fingerprint {
		return fmt.Errorf("setup directory belongs to a different constraint system")
	}
	vk := new(native.VerifyingKey)
	if err = readKey(filepath.Join(directory, "verifying.key"), vk); err != nil {
		return err
	}
	if err = s.useKey(vk); err != nil {
		return err
	}
	s.pk = groth16.NewProvingKey(ecc.BLS12_381)
	return readKey(filepath.Join(directory, "proving.key"), s.pk)
}

func parse32(text string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != len(out) {
		return out, fmt.Errorf("expected 32 bytes encoded as hex")
	}
	copy(out[:], b)
	return out, nil
}

func (s *provingState) readPrior(path string) (issuedProof, error) {
	if filepath.Clean(path) == "." {
		return issuedProof{}, fmt.Errorf("missing prior file")
	}
	var art proofArtifact
	data, err := os.ReadFile(path)
	if err != nil {
		return issuedProof{}, err
	}
	if err = json.Unmarshal(data, &art); err != nil {
		return issuedProof{}, err
	}
	p, digest, err := art.proof()
	if err != nil {
		return issuedProof{}, err
	}
	if err = nativeVerify(s.vk, p, digest); err != nil {
		return issuedProof{}, fmt.Errorf("prior proof %s under the configured key: %w", path, err)
	}
	proof, err := recursive.ValueOfProof[G1, G2](p)
	return issuedProof{proof, digest}, err
}

func run(mode, directory, assetHex, contextHex, output string, paths []string) error {
	if mode == "session" {
		return runSession(directory)
	}
	s, padKey, err := compile()
	if err != nil {
		return err
	}
	switch mode {
	case "probe":
		if err = s.useKey(padKey); err != nil {
			return err
		}
		return s.solve("base shape", s.makeWitness(s.transcript(sha256.Sum256([]byte("probe asset")), sha256.Sum256([]byte("probe base")))), true)
	case "setup", "demo":
		if directory == "" {
			return fmt.Errorf("supply -dir for a fresh private output directory")
		}
		if err = os.Mkdir(directory, 0700); err != nil {
			return err
		}
		start := time.Now()
		pk, vk, err := groth16.Setup(s.ccs)
		if err != nil {
			return err
		}
		s.pk = pk
		if err = s.useKey(vk.(*native.VerifyingKey)); err != nil {
			return err
		}
		fmt.Printf("continuity setup: %v, independently derived self key %x\n", time.Since(start), s.keyDigest)
		if err = writeJSON(filepath.Join(directory, "key.json"), s.artifact); err != nil {
			return err
		}
		start = time.Now()
		if err = s.saveKeys(directory); err != nil {
			return err
		}
		fmt.Printf("saved setup cache in %v\n", time.Since(start))
		if mode == "demo" {
			return s.demo(directory)
		}
		return nil
	case "prove":
		if directory == "" || output == "" || len(paths) > 2 {
			return fmt.Errorf("provide -dir, -out, -asset, -context and 0–2 predecessor artifacts")
		}
		asset, err := parse32(assetHex)
		if err != nil {
			return fmt.Errorf("asset: %w", err)
		}
		context, err := parse32(contextHex)
		if err != nil {
			return fmt.Errorf("transaction context: %w", err)
		}
		start := time.Now()
		if err = s.loadKeys(directory); err != nil {
			return err
		}
		fmt.Printf("loaded continuity cache in %v\n", time.Since(start))
		var priors []issuedProof
		for _, path := range paths {
			prior, err := s.readPrior(path)
			if err != nil {
				return err
			}
			priors = append(priors, prior)
		}
		_, err = s.prove("continuity", output, s.transcript(asset, context, priors...), priors...)
		return err
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}

func main() {
	mode := flag.String("mode", "probe", "probe, setup, demo, prove, or session")
	dir := flag.String("dir", "", "experimental setup directory")
	asset := flag.String("asset", "", "32-byte asset SHA256d in hex")
	context := flag.String("context", "", "32-byte transaction context SHA256d in hex")
	out := flag.String("out", "", "output proof JSON path for -mode prove")
	flag.Parse()
	if err := run(*mode, *dir, *asset, *context, *out, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
