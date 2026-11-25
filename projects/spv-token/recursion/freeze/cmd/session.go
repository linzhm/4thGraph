package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark/logger"
)

// proverSession loads and fingerprints the same parameters as one-shot prove.
// Each line is an independent request. stdout contains only JSONL responses.
func proverSession(directory, profile string) error {
	logger.SetOutput(os.Stderr)
	s, err := loadProver(directory, profile)
	if err != nil {
		return err
	}
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(map[string]any{"ready": true, "profile": s.manifest.Profile, "verifying_key_sha256": s.manifest.VerifyingSHA256}); err != nil {
		return err
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var req struct {
			ID        string `json:"id"`
			Statement string `json:"statement"`
			Openings  string `json:"openings"`
			Parent    string `json:"parent"`
			Out       string `json:"out"`
		}
		err := json.Unmarshal(in.Bytes(), &req)
		if err == nil && (req.Out == "" || req.Statement == "") {
			err = fmt.Errorf("expected statement and new output path")
		}
		if err == nil {
			err = s.prove(req.Statement, req.Parent, req.Openings, req.Out, os.Stderr)
		}
		reply := map[string]any{"id": req.ID, "ok": err == nil}
		if err != nil {
			reply["error"] = err.Error()
		}
		if err := out.Encode(reply); err != nil {
			return err
		}
	}
	return in.Err()
}
