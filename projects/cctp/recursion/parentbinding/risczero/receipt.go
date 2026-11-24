// Package risczero probes native verification of the upstream RISC Zero 3.1
// fixture. It pins the fixture guest and proof system and makes no assertion
// about the proposed CCTP guest or a BSV Script verifier.
package risczero

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// risc0/risc0-ethereum v3.1.0, commit ff30da77ba4afdd496290ebebedb205348b15d83.
// ControlID.sol and TestReceiptV3_1.sol supply these parameter and image bytes.
const (
	selectorHex  = "e71e6620"
	controlRoot  = "e6feef13db7aed4a731c7b0852de1f5c89b137726073f625d05333184d3a551d"
	bn254Control = "0ac2eaf9d5ae64ffb75c4747fde32456e9ee6db3b32350cb2a0614ba91d081de"
	imageHex     = "c92414d80cdeb43ba0f4ff4882447c21f18b547d41ffa506a84da164e8e31f7d"
	g1Bytes      = bn254.SizeOfG1AffineUncompressed
	g2Bytes      = bn254.SizeOfG2AffineUncompressed
)

var (
	imageID      = [32]byte(mustHex(imageHex))
	root         = [32]byte(mustHex(controlRoot))
	control      = [32]byte(mustHex(bn254Control))
	selector     = [4]byte(mustHex(selectorHex))
	key          = fixedKey()
	invalidProof = errors.New("RISC Zero Groth16 pairing did not verify")
)

// VerifyFixture authenticates journal bytes for the pinned TestReceiptV3_1
// image using the patched 3.1.0 verifier parameters.
func VerifyFixture(seal, journal []byte) error {
	return verifyReceipt(seal, imageID, journal)
}

func verifyReceipt(seal []byte, image [32]byte, journal []byte) error {
	if len(seal) != len(selector)+g1Bytes+g2Bytes+g1Bytes {
		return errors.New("incorrect RISC Zero seal length")
	}
	if [4]byte(seal[:4]) != selector {
		return errors.New("incorrect RISC Zero v3.1.0 seal selector")
	}
	proof := seal[4:]
	var a, c bn254.G1Affine
	var b bn254.G2Affine
	if err := decodePoint(&a, proof[:g1Bytes]); err != nil {
		return fmt.Errorf("proof A: %w", err)
	}
	if err := decodePoint(&b, proof[g1Bytes:g1Bytes+g2Bytes]); err != nil {
		return fmt.Errorf("proof B: %w", err)
	}
	if err := decodePoint(&c, proof[g1Bytes+g2Bytes:]); err != nil {
		return fmt.Errorf("proof C: %w", err)
	}

	acc := key.ic[0]
	modulus := fr.Modulus()
	for i, signal := range publicSignals(successClaim(image, journal)) {
		if signal.Cmp(modulus) >= 0 {
			return errors.New("RISC Zero public input outside the BN254 scalar field")
		}
		var term bn254.G1Affine
		term.ScalarMultiplication(&key.ic[i+1], signal)
		acc.Add(&acc, &term)
	}
	a.Neg(&a)
	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{a, key.alpha, acc, c},
		[]bn254.G2Affine{b, key.beta, key.gamma, key.delta},
	)
	if err != nil {
		return err
	}
	if !ok {
		return invalidProof
	}
	return nil
}

func successClaim(image [32]byte, journal []byte) [32]byte {
	var zero [32]byte
	endState := tagged("risc0.SystemState", make([]byte, 4), zero)
	output := tagged("risc0.Output", nil, sha256.Sum256(journal), zero)
	return tagged("risc0.ReceiptClaim", make([]byte, 8), zero, image, endState, output)
}

func tagged(label string, data []byte, children ...[32]byte) [32]byte {
	tag := sha256.Sum256([]byte(label))
	preimage := make([]byte, 0, len(tag)+32*len(children)+len(data)+2)
	preimage = append(preimage, tag[:]...)
	for _, child := range children {
		preimage = append(preimage, child[:]...)
	}
	preimage = append(preimage, data...)
	preimage = binary.LittleEndian.AppendUint16(preimage, uint16(len(children)))
	return sha256.Sum256(preimage)
}

func publicSignals(claim [32]byte) [5]*big.Int {
	// Root and claim use two little-endian uint128 halves in wire order.
	// The separately pinned BN254 control word is one big-endian scalar.
	return [5]*big.Int{
		littleEndian(root[:16]), littleEndian(root[16:]),
		littleEndian(claim[:16]), littleEndian(claim[16:]),
		new(big.Int).SetBytes(control[:]),
	}
}

func littleEndian(raw []byte) *big.Int {
	swapped := slices.Clone(raw)
	slices.Reverse(swapped)
	return new(big.Int).SetBytes(swapped)
}

type encodedPoint interface {
	SetBytes([]byte) (int, error)
	IsInfinity() bool
}

func decodePoint(point encodedPoint, raw []byte) error {
	// EIP-197 ABI order matches gnark's uncompressed order, including G2
	// coefficients x1,x0,y1,y0. SetBytes validates canonical field values,
	// curve membership and subgroup membership.
	n, err := point.SetBytes(raw)
	if err != nil {
		return err
	}
	if n != len(raw) || point.IsInfinity() {
		return errors.New("expected a complete uncompressed BN254 point")
	}
	return nil
}

type verificationKey struct {
	alpha              bn254.G1Affine
	beta, gamma, delta bn254.G2Affine
	ic                 [6]bn254.G1Affine
}

func fixedKey() verificationKey {
	var vk verificationKey
	raw := mustHex(verifierKeyHex)
	load := func(dest encodedPoint, size int) {
		if err := decodePoint(dest, raw[:size]); err != nil {
			panic(err)
		}
		raw = raw[size:]
	}
	load(&vk.alpha, g1Bytes)
	load(&vk.beta, g2Bytes)
	load(&vk.gamma, g2Bytes)
	load(&vk.delta, g2Bytes)
	for i := range vk.ic {
		load(&vk.ic[i], g1Bytes)
	}
	if len(raw) != 0 {
		panic("extra bytes in the pinned RISC Zero verification key")
	}
	return vk
}

func mustHex(raw string) []byte {
	bytes, err := hex.DecodeString(raw)
	if err != nil {
		panic(err)
	}
	return bytes
}

// EIP-197 coordinate words from v3.1.0 contracts/src/groth16/Groth16Verifier.sol.
const verifierKeyHex =
// alpha
"245229d9b076b3c0e8a4d70bde8c1cccffa08a9fae7557b165b3b0dbd653e2c7" +
	"253ec85988dbb84e46e94b5efa3373b47a000b4ac6c86b2d4b798d274a182302" +
	// beta
	"07090a82e8fabbd39299be24705b92cf208ee8b3487f6f2b39ff27978a29a1db" +
	"2424bcc1f60a5472685fd50705b2809626e170120acaf441e133a2bd5e61d244" +
	"0ae1135cffdaf227c5dc266740607aa930bc3bd92ddc2b135086d9da2dfd3e2a" +
	"2b86859fd3d55c9d150fb3f0aeba798826493dd73d357ab0f9fdaced9fc81829" +
	// gamma
	"198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2" +
	"1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed" +
	"090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b" +
	"12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa" +
	// delta
	"2286b6b2c093a9813e01c3bf8f4b03c60b01409fd433bbb7ccccd7458907f8ac" +
	"22e147b6d5be7d9e6864f4a92cd04ce58bcd2d991de3a19d0223a7dacc90544c" +
	"227f6bb0cfd57252d41763099dc20b72d95f2ca864913d0e174617263d7f388b" +
	"0ebd3c619a32a0531d24233fcd2720d9267c046b53fe2dd660367b21ba61c928" +
	// IC0
	"2943674feb63c48529eb9657dafe7c1b3bed74960c9561229b4b1495d434c5d8" +
	"2600aba15653fe46bbdc330f45eb74845e0c0b6d9e484f791a147dde5df3b1ea" +
	// IC1
	"184f5250d6a420bcc0e64f40a01a4905d6c2882718f4d79b4a45e8728763da12" +
	"253b22115032bde5cb1e076a4d8daf47deea4afd244a2c04d0ad40e8b17baeeb" +
	// IC2
	"26144b7b31c87836f3351f97d6505c82be5b265113bd79bd89bbf2afd019b772" +
	"090c1bf455048af08a8401d210d5fa2594b0f45ce968c354135e98f0513bc924" +
	// IC3
	"085308ff4ed53c8c3c36da93488bc9d78224863ba906bd9e527eecf36aee9c81" +
	"1afebdd055565d9bf453cb6eec5a57700a29cdcd319cd21333fe04c8c6a4e19f" +
	// IC4
	"1693c6c2335c8c200844de665c727e57e4ffe6ecd6cfbb96979d2b10d96ff6ca" +
	"0ea71982c117da36448eaed1b8ba4ba93d391f3fc4dd59a108056cf45c7e859c" +
	// IC5
	"1dbf0e7b71899b6f210bcfdfb048b545cfb3cdf2dc7c6ce799ff817e04f41970" +
	"134df41c104d7b0016a7bd0a363616a36de0a60d6b59044e7897131a50ae4fde"
