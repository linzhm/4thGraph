package p2pkhr1

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"

	"golang.org/x/crypto/ripemd160"
)

// TxID uses display byte order. InputScript and InputSatoshis come from the authenticated UTXO.
type Payment struct {
	TxID          [32]byte
	Vout          uint32
	InputSatoshis int64
	InputScript   []byte
	Outputs       []Output
	Fee           int64
}

type Output struct {
	Satoshis int64
	Script   []byte
}

const maxAmount int64 = 2_100_000_000_000_000

func hash256(b []byte) [32]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

func compactSize(n int) []byte {
	switch {
	case n < 253:
		return []byte{byte(n)}
	case n <= 65535:
		return binary.LittleEndian.AppendUint16([]byte{253}, uint16(n))
	case uint64(n) <= 0xffffffff:
		return binary.LittleEndian.AppendUint32([]byte{254}, uint32(n))
	default:
		return binary.LittleEndian.AppendUint64([]byte{255}, uint64(n))
	}
}

// SignPayment authorizes one input with ForkID ALL. The callback signs a digest once.
func SignPayment(p Payment, publicKey []byte, signDigest func([32]byte) ([]byte, error)) ([]byte, error) {
	if signDigest == nil {
		return nil, errors.New("invalid payment")
	}
	return SignPaymentWithMessage(p, publicKey, func(message [32]byte) ([]byte, error) {
		return signDigest(sha256.Sum256(message[:]))
	})
}

// SignPaymentWithMessage passes SHA256(P) to a signer that applies SHA-256 internally.
func SignPaymentWithMessage(p Payment, publicKey []byte, signMessage func([32]byte) ([]byte, error)) ([]byte, error) {
	q := bytes.Clone(publicKey)
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, q)
	if x == nil {
		return nil, errors.New("expected uncompressed P-256 public key")
	}
	if p.InputSatoshis > maxAmount {
		return nil, errors.New("invalid input amount")
	}
	owner, ok := Recognize(p.InputScript)
	keyHash := sha256.Sum256(q)
	h := ripemd160.New()
	h.Write(keyHash[:])
	if !ok || !bytes.Equal(owner[:], h.Sum(nil)) {
		return nil, errors.New("wrong funding lock")
	}
	if len(p.Outputs) == 0 || p.Fee < 0 || p.InputSatoshis < p.Fee || signMessage == nil {
		return nil, errors.New("invalid payment")
	}
	balance := p.InputSatoshis - p.Fee
	var outputs bytes.Buffer
	for _, o := range p.Outputs {
		if o.Satoshis < 0 || o.Satoshis > balance {
			return nil, errors.New("output exceeds available funds")
		}
		balance -= o.Satoshis
		outputs.Write(binary.LittleEndian.AppendUint64(nil, uint64(o.Satoshis)))
		outputs.Write(compactSize(len(o.Script)))
		outputs.Write(o.Script)
	}
	if balance != 0 {
		return nil, errors.New("payment does not balance")
	}

	slices.Reverse(p.TxID[:])
	outpoint := binary.LittleEndian.AppendUint32(bytes.Clone(p.TxID[:]), p.Vout)
	version := []byte{2, 0, 0, 0}
	sequence := []byte{255, 255, 255, 255}
	locktime := []byte{0, 0, 0, 0}
	prevHash, seqHash, outHash := hash256(outpoint), hash256(sequence), hash256(outputs.Bytes())
	value := binary.LittleEndian.AppendUint64(nil, uint64(p.InputSatoshis))
	pre := bytes.Join([][]byte{version, prevHash[:], seqHash[:], outpoint, {2, 0x68, 0xac},
		value, sequence, outHash[:], locktime, {0x41, 0, 0, 0}}, nil)
	message := sha256.Sum256(pre)
	digest := sha256.Sum256(message[:])
	sig, err := signMessage(message)
	if err != nil {
		return nil, err
	}
	if len(sig) != 64 {
		return nil, errors.New("expected a 64-byte R1 signature")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, digest[:], r, s) {
		return nil, errors.New("invalid R1 digest signature")
	}
	inverse := new(big.Int).ModInverse(s, curve.Params().N).FillBytes(make([]byte, 32))
	slices.Reverse(inverse)
	witness := bytes.Join([][]byte{{0x4c, byte(len(pre))}, pre, {65}, q, {64}, sig, {32}, inverse, {0}}, nil)
	return bytes.Join([][]byte{version, {1}, outpoint, compactSize(len(witness)), witness,
		sequence, compactSize(len(p.Outputs)), outputs.Bytes(), locktime}, nil), nil
}
