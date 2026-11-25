package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark/logger"
)

type proofRequest struct {
	ID      string   `json:"id"`
	Asset   string   `json:"asset"`
	Context string   `json:"context"`
	Prior   []string `json:"prior"`
	Out     string   `json:"out"`
}

type proofResponse struct {
	OK     bool   `json:"ok"`
	ID     string `json:"id,omitempty"`
	Output string `json:"out,omitempty"`
	Digest string `json:"digest,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (s *provingState) request(req proofRequest) (issuedProof, error) {
	if len(req.Prior) > 2 || req.Out == "" {
		return issuedProof{}, fmt.Errorf("provide an output file and zero to two prior files")
	}
	asset, err := parse32(req.Asset)
	if err != nil {
		return issuedProof{}, fmt.Errorf("asset: %w", err)
	}
	context, err := parse32(req.Context)
	if err != nil {
		return issuedProof{}, fmt.Errorf("transaction context: %w", err)
	}
	priors := make([]issuedProof, 0, len(req.Prior))
	for _, path := range req.Prior {
		prior, err := s.readPrior(path)
		if err != nil {
			return issuedProof{}, err
		}
		priors = append(priors, prior)
	}
	return s.prove("continuity", req.Out, s.transcript(asset, context, priors...), priors...)
}

// runSession keeps an authenticated local setup in memory for dependent
// requests. stdout carries JSONL replies and stderr carries runtime logs.
func runSession(directory string) error {
	if directory == "" {
		return fmt.Errorf("session requires a setup directory")
	}
	progress = os.Stderr
	logger.SetOutput(os.Stderr)
	s, _, err := compile()
	if err != nil {
		return err
	}
	start := time.Now()
	if err := s.loadKeys(directory); err != nil {
		return err
	}
	fmt.Fprintf(progress, "loaded continuity cache in %v\n", time.Since(start))
	output := json.NewEncoder(os.Stdout)
	if err := output.Encode(map[string]any{"ready": true, "continuity_key_digest": s.artifact.SelfDigest}); err != nil {
		return err
	}
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		var req proofRequest
		response := proofResponse{}
		if err := json.Unmarshal(input.Bytes(), &req); err != nil {
			response.Error = "invalid JSON request: " + err.Error()
		} else {
			response.ID = req.ID
			proof, err := s.request(req)
			if err != nil {
				response.Error = err.Error()
			} else {
				response.OK = true
				response.Output = req.Out
				response.Digest = hex.EncodeToString(proof.digest[:])
			}
		}
		if err := output.Encode(response); err != nil {
			return err
		}
	}
	return input.Err()
}
