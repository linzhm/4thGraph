// Command freeze creates test-only Groth16 parameters and proves CCTP statements.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	recursive "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/conservation"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/freeze"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/inventoryorigin"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/inventoryprove"
	"github.com/linzhm/BSV-Script-Lab/projects/cctp/recursion/parentcheckpoint"
)

const (
	originProfile               = "inventory-origin"
	originFormat                = "CCTP inventory origin test parameters v1"
	inventoryProfile            = "inventory-payment"
	inventoryFormat             = "CCTP inventory payment test parameters v1"
	plainProfile                = "plain"
	bsb22Profile                = "bsb22"
	conservationProfile         = "conservation"
	parentCheckpointProfile     = "parent-checkpoint"
	tokenCheckpointProfile      = "parent-checkpoint-token"
	parameterFormat             = "CCTP freeze test parameters v1"
	conservationParameterFormat = "CCTP conservation test parameters v1"
	parentCheckpointFormat      = "CCTP parent checkpoint test parameters v1"
	tokenCheckpointFormat       = "CCTP token parent checkpoint test parameters v1"
	manifestName                = "manifest.json"
	verifyingKeyName            = "verifying.key"
	provingKeyName              = "proving.key"
)

type manifest struct {
	Format          string `json:"format"`
	Profile         string `json:"profile"`
	TestOnly        bool   `json:"test_only"`
	Constraints     int    `json:"constraints"`
	Commitments     int    `json:"commitments"`
	StatementBytes  int    `json:"statement_bytes"`
	CircuitSHA256   string `json:"circuit_sha256"`
	VerifyingSHA256 string `json:"verifying_key_sha256"`
	ProvingSHA256   string `json:"proving_key_sha256"`
}

func compileFreeze(profile string) (constraint.ConstraintSystem, manifest, error) {
	m := manifest{Format: parameterFormat, Profile: profile, TestOnly: true, StatementBytes: freeze.EncodedSize}
	privateBytes := freeze.PayloadSize
	var circuit frontend.Circuit
	switch profile {
	case originProfile:
		circuit = &inventoryorigin.Circuit{}
		m.Format, m.StatementBytes = originFormat, inventoryorigin.StatementSize
		privateBytes = inventoryorigin.OpeningSize
	case plainProfile:
		circuit = &freeze.PlainCircuit{}
	case bsb22Profile:
		circuit = &freeze.Circuit{}
		m.Commitments = 1
	case conservationProfile:
		circuit = &conservation.Circuit{}
		m.Format, m.StatementBytes = conservationParameterFormat, conservation.EncodedSize
		privateBytes = conservation.PayloadSize
	case inventoryProfile:
		circuit = &inventoryprove.Circuit{}
		m.Format, m.StatementBytes = inventoryFormat, inventoryprove.PaymentSize
		privateBytes = inventoryprove.PaymentSize - 1 + inventoryprove.WitnessSize
	case parentCheckpointProfile:
		circuit = &parentcheckpoint.Circuit{}
		m.Format, m.StatementBytes = parentCheckpointFormat, parentcheckpoint.EncodedSize
		privateBytes = parentcheckpoint.ParentSize
	case tokenCheckpointProfile:
		circuit = &parentcheckpoint.TokenCircuit{}
		m.Format, m.StatementBytes = tokenCheckpointFormat, parentcheckpoint.EncodedSize
		privateBytes = parentcheckpoint.TokenParentSize
	default:
		return nil, m, fmt.Errorf("unknown circuit profile %q", profile)
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, m, err
	}
	commitments, ok := ccs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != m.Commitments || ccs.GetNbPublicVariables() != 3 ||
		ccs.GetNbSecretVariables() != privateBytes {
		return nil, m, fmt.Errorf("unexpected public, private or commitment dimensions for %s", profile)
	}
	if profile == bsb22Profile && len(commitments[0].GetPublicCommitted()) != 0 {
		return nil, m, fmt.Errorf("expected no public BSB22 commitment indexes")
	}
	m.Constraints = ccs.GetNbConstraints()
	hash := sha256.New()
	if _, err := ccs.WriteTo(hash); err != nil {
		return nil, m, err
	}
	m.CircuitSHA256 = hex.EncodeToString(hash.Sum(nil))
	return ccs, m, nil
}

func writeNew(path string, encode func(io.Writer) error) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	buffer := bufio.NewWriterSize(file, 1<<20)
	err = encode(buffer)
	if err == nil {
		err = buffer.Flush()
	}
	if err == nil {
		err = file.Sync()
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	return os.Link(file.Name(), path)
}

func writeJSON(path string, value any) error {
	return writeNew(path, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	})
}

func writeNative(path string, object io.WriterTo) (string, error) {
	hash := sha256.New()
	err := writeNew(path, func(w io.Writer) error {
		_, err := object.WriteTo(io.MultiWriter(w, hash))
		return err
	})
	return hex.EncodeToString(hash.Sum(nil)), err
}

func readNative(path, digest string, object io.ReaderFrom) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	reader := bufio.NewReaderSize(io.TeeReader(file, hash), 1<<20)
	if _, err := object.ReadFrom(reader); err != nil {
		return err
	}
	if _, err := reader.Peek(1); err != io.EOF {
		return fmt.Errorf("expected end of native setup file %s", filepath.Base(path))
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("native setup file %s differs from the manifest", filepath.Base(path))
	}
	return nil
}

func setup(directory, profile string) error {
	if profile == "" {
		profile = plainProfile
	}
	switch profile {
	case originProfile, inventoryProfile, plainProfile, bsb22Profile, conservationProfile, parentCheckpointProfile, tokenCheckpointProfile:
	default:
		return fmt.Errorf("unknown circuit profile %q", profile)
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	ccs, m, err := compileFreeze(profile)
	if err != nil {
		return err
	}
	fmt.Printf("compiled %s: %d constraints, %d commitments, fingerprint %s\n",
		profile, m.Constraints, m.Commitments, m.CircuitSHA256)
	started := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}
	m.ProvingSHA256, err = writeNative(filepath.Join(directory, provingKeyName), pk)
	if err != nil {
		return err
	}
	m.VerifyingSHA256, err = writeNative(filepath.Join(directory, verifyingKeyName), vk)
	if err != nil {
		return err
	}
	key, err := keyArtifact(m, vk.(*native.VerifyingKey))
	if err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(directory, "key.json"), key); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(directory, manifestName), m); err != nil {
		return err
	}
	fmt.Printf("%s: %d constraints, test setup %s, verifying key %s\n",
		profile, m.Constraints, time.Since(started), m.VerifyingSHA256)
	return nil
}

func loadManifest(directory string) (manifest, error) {
	var m manifest
	file, err := os.ReadFile(filepath.Join(directory, manifestName))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(file, &m); err != nil {
		return m, err
	}
	expectedFormat, expectedBytes := parameterFormat, freeze.EncodedSize
	switch m.Profile {
	case originProfile:
		expectedFormat, expectedBytes = originFormat, inventoryorigin.StatementSize
	case inventoryProfile:
		expectedFormat, expectedBytes = inventoryFormat, inventoryprove.PaymentSize
	case conservationProfile:
		expectedFormat, expectedBytes = conservationParameterFormat, conservation.EncodedSize
	case parentCheckpointProfile:
		expectedFormat, expectedBytes = parentCheckpointFormat, parentcheckpoint.EncodedSize
	case tokenCheckpointProfile:
		expectedFormat, expectedBytes = tokenCheckpointFormat, parentcheckpoint.EncodedSize
	}
	if m.Format != expectedFormat || !m.TestOnly || m.StatementBytes != expectedBytes {
		return m, fmt.Errorf("expected completed test-only CCTP parameters")
	}
	return m, nil
}

func parseStatement(wire string) (freeze.Statement, error) {
	if len(wire) != 2*freeze.EncodedSize {
		return freeze.Statement{}, fmt.Errorf("expected %d freeze statement bytes encoded as hex", freeze.EncodedSize)
	}
	raw, err := hex.DecodeString(wire)
	if err != nil {
		return freeze.Statement{}, fmt.Errorf("invalid freeze statement hex: %w", err)
	}
	return freeze.ParseStatement(raw)
}

func assignmentFor(profile, wire, parent string) (proofStatement, frontend.Circuit, error) {
	if profile == originProfile || profile == inventoryProfile {
		payment, err := hex.DecodeString(wire)
		if err != nil {
			return nil, nil, err
		}
		openings, err := hex.DecodeString(parent)
		if err != nil {
			return nil, nil, err
		}
		if profile == originProfile {
			return inventoryorigin.Decode(payment, openings)
		}
		return inventoryprove.Decode(payment, openings)
	}
	if profile == parentCheckpointProfile || profile == tokenCheckpointProfile {
		return checkpointAssignment(profile, wire, parent)
	}
	if parent != "" {
		return nil, nil, fmt.Errorf("-parent is only valid for parent checkpoint profiles")
	}
	if profile == conservationProfile {
		if len(wire) != 2*conservation.EncodedSize {
			return nil, nil, fmt.Errorf("expected %d conservation statement bytes encoded as hex", conservation.EncodedSize)
		}
		raw, err := hex.DecodeString(wire)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid conservation statement hex: %w", err)
		}
		statement, err := conservation.ParseStatement(raw)
		if err != nil {
			return nil, nil, err
		}
		return statement, statement.Assignment(), nil
	}
	statement, err := parseStatement(wire)
	if err != nil {
		return nil, nil, err
	}
	if profile == bsb22Profile {
		return statement, statement.Assignment(), nil
	}
	return statement, statement.PlainAssignment(), nil
}

func checkpointAssignment(profile, wire, parent string) (proofStatement, frontend.Circuit, error) {
	if len(wire) != 2*parentcheckpoint.EncodedSize {
		return nil, nil, fmt.Errorf("expected %d parent checkpoint statement bytes encoded as hex", parentcheckpoint.EncodedSize)
	}
	raw, err := hex.DecodeString(wire)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid parent checkpoint statement hex: %w", err)
	}
	statement, err := parentcheckpoint.ParseStatement(raw)
	if err != nil {
		return nil, nil, err
	}
	parentSize := parentcheckpoint.ParentSize
	if profile == tokenCheckpointProfile {
		parentSize = parentcheckpoint.TokenParentSize
	}
	if len(parent) != 2*parentSize {
		return nil, nil, fmt.Errorf("expected %d parent transaction bytes encoded as hex in -parent", parentSize)
	}
	parentRaw, err := hex.DecodeString(parent)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid parent transaction hex: %w", err)
	}
	if profile == tokenCheckpointProfile {
		assignment, err := statement.TokenAssignment(parentRaw)
		return statement, assignment, err
	}
	assignment, err := statement.Assignment(parentRaw)
	return statement, assignment, err
}

type loadedProver struct {
	manifest manifest
	ccs      constraint.ConstraintSystem
	pk       groth16.ProvingKey
	vk       *native.VerifyingKey
}

func loadProver(directory, profile string) (*loadedProver, error) {
	saved, err := loadManifest(directory)
	if err != nil {
		return nil, err
	}
	if profile != "" && profile != saved.Profile {
		return nil, fmt.Errorf("requested profile does not match the completed setup")
	}
	ccs, expected, err := compileFreeze(saved.Profile)
	if err != nil {
		return nil, err
	}
	expected.ProvingSHA256, expected.VerifyingSHA256 = saved.ProvingSHA256, saved.VerifyingSHA256
	if expected != saved {
		return nil, fmt.Errorf("setup manifest belongs to a different CCTP constraint system")
	}
	pk := groth16.NewProvingKey(ecc.BLS12_381)
	vk := new(native.VerifyingKey)
	if err := readNative(filepath.Join(directory, verifyingKeyName), saved.VerifyingSHA256, vk); err != nil {
		return nil, err
	}
	if err := readNative(filepath.Join(directory, provingKeyName), saved.ProvingSHA256, pk); err != nil {
		return nil, err
	}
	return &loadedProver{manifest: saved, ccs: ccs, pk: pk, vk: vk}, nil
}

func (s *loadedProver) prove(wire, parent, openings, output string, log io.Writer) error {
	saved := s.manifest
	if _, err := os.Lstat(output); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("choose a new proof output path: %s", output)
	}
	if saved.Profile == inventoryProfile || saved.Profile == originProfile {
		if parent != "" {
			return fmt.Errorf("inventory profile expects -openings")
		}
		parent = openings
	} else if openings != "" {
		return fmt.Errorf("-openings requires an inventory profile")
	}
	statement, assignment, err := assignmentFor(saved.Profile, wire, parent)
	if err != nil {
		return err
	}
	key, err := keyArtifact(saved, s.vk)
	if err != nil {
		return err
	}
	field := ecc.BLS12_381.ScalarField()
	var provingOptions []backend.ProverOption
	var verificationOptions []backend.VerifierOption
	if saved.Profile == bsb22Profile {
		provingOptions = append(provingOptions, recursive.GetNativeProverOptions(field, field))
		verificationOptions = append(verificationOptions, recursive.GetNativeVerifierOptions(field, field))
	}
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return err
	}
	started := time.Now()
	proof, err := groth16.Prove(s.ccs, s.pk, witness, provingOptions...)
	provedAt := time.Now()
	if err != nil {
		return fmt.Errorf("%s witness does not prove: %w", saved.Profile, err)
	}
	public, err := witness.Public()
	if err != nil {
		return err
	}
	verificationStarted := time.Now()
	if err := groth16.Verify(proof, s.vk, public, verificationOptions...); err != nil {
		return fmt.Errorf("generated proof failed native verification: %w", err)
	}
	verificationElapsed := time.Since(verificationStarted)
	if err := addProof(key, saved.Profile, proof.(*native.Proof), statement); err != nil {
		return err
	}
	key["prove_seconds"] = provedAt.Sub(started).Seconds()
	key["native_verify_seconds"] = verificationElapsed.Seconds()
	if err := writeJSON(output, key); err != nil {
		return err
	}
	fmt.Fprintf(log, "%s: proved and verified in %s, statement %x\n", saved.Profile, time.Since(started), statement.Digest())
	return nil
}

func prove(directory, profile, wire, parent, openings, output string) error {
	s, err := loadProver(directory, profile)
	if err != nil {
		return err
	}
	return s.prove(wire, parent, openings, output, os.Stdout)
}

func main() {
	mode := flag.String("mode", "", "setup, prove, or session")
	profile := flag.String("profile", "", "plain (setup default), bsb22, conservation, parent-checkpoint, parent-checkpoint-token, or an inventory profile; prove reads the setup profile")
	directory := flag.String("dir", "", "fresh setup directory or completed setup to reuse")
	wire := flag.String("statement", "", "exact versioned statement encoded as hex")
	parent := flag.String("parent", "", "actual parent transaction hex for a parent checkpoint proof")
	openings := flag.String("openings", "", "private witness encoding, hex, for the selected inventory profile")
	output := flag.String("out", "", "new proof JSON path")
	flag.Parse()
	var err error
	switch {
	case flag.NArg() != 0 || *directory == "":
		err = fmt.Errorf("provide -mode and -dir; positional arguments are unsupported")
	case *mode == "setup" && *wire == "" && *parent == "" && *openings == "" && *output == "":
		err = setup(*directory, *profile)
	case *mode == "session" && *wire == "" && *parent == "" && *openings == "" && *output == "":
		err = proverSession(*directory, *profile)
	case *mode == "prove" && *wire != "" && *output != "":
		err = prove(*directory, *profile, *wire, *parent, *openings, *output)
	default:
		err = fmt.Errorf("use setup with -dir or prove with -dir, -statement and -out")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
