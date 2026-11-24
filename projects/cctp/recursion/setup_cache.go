package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

func provingSetup(ccs constraint.ConstraintSystem, cachePath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	if cachePath == "" {
		return groth16.Setup(ccs)
	}
	hash := sha256.New()
	if _, err := ccs.WriteTo(hash); err != nil {
		return nil, nil, fmt.Errorf("fingerprint compiled constraints: %w", err)
	}
	fingerprint := "cctp-recursion-gnark-v0.16.5-bls12-381 " + hex.EncodeToString(hash.Sum(nil)) + "\n"
	cachePath = filepath.Clean(cachePath)
	cached, err := os.ReadFile(filepath.Join(cachePath, "circuit.txt"))
	if err == nil {
		if string(cached) != fingerprint {
			return nil, nil, fmt.Errorf("cached setup belongs to a different constraint system")
		}
		fmt.Println("reading the setup for the identical constraint system")
		pk, vk := groth16.NewProvingKey(ecc.BLS12_381), groth16.NewVerifyingKey(ecc.BLS12_381)
		if err = readKey(cachePath, "proving.key", pk); err != nil {
			return nil, nil, err
		}
		if err = readKey(cachePath, "verifying.key", vk); err != nil {
			return nil, nil, err
		}
		return pk, vk, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, err
	}
	if _, err := os.Lstat(cachePath); !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("setup directory exists without a complete manifest")
	}
	tmp, err := os.MkdirTemp(filepath.Dir(cachePath), ".cctp-setup-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmp)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, err
	}
	if err = writeKey(tmp, "proving.key", pk); err != nil {
		return nil, nil, err
	}
	if err = writeKey(tmp, "verifying.key", vk); err != nil {
		return nil, nil, err
	}
	if err = os.WriteFile(filepath.Join(tmp, "circuit.txt"), []byte(fingerprint), 0600); err != nil {
		return nil, nil, err
	}
	if err = os.Rename(tmp, cachePath); err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}

func readKey(directory, name string, reader io.ReaderFrom) error {
	file, err := os.Open(filepath.Join(directory, name))
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := reader.ReadFrom(file); err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	return nil
}

func writeKey(directory, name string, writer io.WriterTo) error {
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = writer.WriteTo(file)
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return closeErr
}
