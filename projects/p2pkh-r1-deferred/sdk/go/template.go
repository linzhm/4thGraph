// Package deferred constructs and recognizes canonical P2PKH-R1-Deferred scriptPubKeys.
package deferred

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	r1 "github.com/linzhm/bsv-script-lab/projects/p2pkh-r1/sdk/go"
)

const fingerprint = "c81b70f59e00402fb3cd936d174e7c8a45eb8205a18b3ad43fac29e93f58ccb4"

type Commitment struct {
	OwnerHash160       [20]byte
	PublicKey          [65]byte // Zero unless the previous output disclosed a full public key.
	TargetScriptSHA256 [32]byte
	TargetTxOutHash256 [32]byte
}

func canonical(script []byte) bool {
	if len(script) != 1435 {
		return false
	}
	fixed := bytes.Clone(script)
	clear(fixed[1:21])
	clear(fixed[22:54])
	clear(fixed[109:117])
	clear(fixed[134:166])
	hash := sha256.Sum256(fixed)
	return hex.EncodeToString(hash[:]) == fingerprint
}

func isLegacy(script []byte) bool {
	return len(script) == 1480 && script[0] == 65 && script[1] == 4
}

func compactTemplate(template []byte, owner [20]byte) []byte {
	if isLegacy(template) {
		script := make([]byte, 1, 1435)
		script[0] = 20
		script = append(script, owner[:]...)
		return append(script, template[66:]...)
	}
	return bytes.Clone(template)
}

func buildLock(template, target []byte, owner [20]byte, satoshis int64) ([]byte, error) {
	script := compactTemplate(template, owner)
	if !canonical(script) {
		return nil, errors.New("unrecognized deferred template")
	}
	if satoshis < 0 || satoshis > 2_100_000_000_000_000 {
		return nil, errors.New("invalid amount")
	}
	value := binary.LittleEndian.AppendUint64(nil, uint64(satoshis))
	output := append(bytes.Clone(value), 0xfd)
	output = binary.LittleEndian.AppendUint16(output, uint16(len(target)))
	output = append(output, target...)
	hash := sha256.Sum256(output)
	outputHash := sha256.Sum256(hash[:])
	if outputHash == [32]byte{} {
		return nil, errors.New("zero target commitment")
	}
	scriptHash := sha256.Sum256(target)
	copy(script[1:21], owner[:])
	copy(script[22:54], scriptHash[:])
	copy(script[109:117], value)
	copy(script[134:166], outputHash[:])
	return script, nil
}

func LockForOwner(template, r1Template []byte, owner [20]byte, satoshis int64) ([]byte, error) {
	target, err := r1.LockForOwner(r1Template, owner)
	if err != nil {
		return nil, err
	}
	return buildLock(template, target, owner, satoshis)
}

func LockForKey(template, r1Template, publicKey []byte, satoshis int64) ([]byte, error) {
	target, err := r1.LockForKey(r1Template, publicKey)
	if err != nil {
		return nil, err
	}
	owner, ok := r1.Recognize(target)
	if !ok {
		return nil, errors.New("unrecognized target R1 lock")
	}
	return buildLock(template, target, owner, satoshis)
}

func Recognize(r1Template, script []byte, satoshis int64) (Commitment, bool) {
	legacy := isLegacy(script)
	if !legacy && len(script) != 1435 {
		return Commitment{}, false
	}
	var key [65]byte
	owner := [20]byte(script[1:21])
	if legacy {
		key = [65]byte(script[1:66])
		target, err := r1.LockForKey(r1Template, key[:])
		if err != nil {
			return Commitment{}, false
		}
		var ok bool
		owner, ok = r1.Recognize(target)
		if !ok {
			return Commitment{}, false
		}
	}
	compact := compactTemplate(script, owner)
	expected, err := LockForOwner(compact, r1Template, owner, satoshis)
	if err != nil || !bytes.Equal(expected, compact) {
		return Commitment{}, false
	}
	return Commitment{OwnerHash160: owner, PublicKey: key, TargetScriptSHA256: [32]byte(compact[22:54]),
		TargetTxOutHash256: [32]byte(compact[134:166])}, true
}

// ActivationWitness encodes the paired output preimage and optional type byte plus selected transaction digest.
func ActivationWitness(r1Template, script []byte, satoshis int64, preimage []byte, auxiliary ...[]byte) ([]byte, error) {
	if len(auxiliary) > 1 {
		return nil, errors.New("expected at most one auxiliary activation digest")
	}
	code := []byte{1, 0xac}
	if len(auxiliary) == 1 {
		code = []byte{4, 0xad, 0x68, 0xab, 0xac}
	}
	valueOffset := 104 + len(code)
	commitment, ok := Recognize(r1Template, script, satoshis)
	if !ok || len(preimage) != valueOffset+52 || !bytes.Equal(preimage[104:valueOffset], code) ||
		binary.LittleEndian.Uint64(preimage[valueOffset:]) != uint64(satoshis) ||
		!bytes.Equal(preimage[valueOffset+12:valueOffset+44], commitment.TargetTxOutHash256[:]) {
		return nil, errors.New("activation preimage does not match the funding output")
	}
	bindingType := binary.LittleEndian.Uint32(preimage[len(preimage)-4:])
	if bindingType != 0x43 && bindingType != 0xc3 {
		return nil, errors.New("expected ForkID SINGLE")
	}
	var witness []byte
	if len(auxiliary) == 1 {
		extra := auxiliary[0]
		if len(extra) != 33 {
			return nil, errors.New("invalid auxiliary activation digest")
		}
		mode := extra[0]
		if mode&0x5f < 0x41 || mode&0x5f > 0x43 || mode == 0x43 || mode == 0xc3 ||
			uint32(mode&0x80) != bindingType&0x80 {
			return nil, errors.New("invalid auxiliary activation type")
		}
		witness = append([]byte{33}, extra...)
	}
	return append(append(witness, 0x4c, byte(len(preimage))), preimage...), nil
}
