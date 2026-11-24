package risczero

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func TestExactV310Fixture(t *testing.T) {
	seal := mustHex(fixtureSealHex)
	journal := mustHex(fixtureJournalHex)
	if got := fmt.Sprintf("%x", sha256.Sum256(seal)); got != "ae2ec9645810e9afdb95ed6aca3280638926952a8dd9178d24b2629d8ae2b8be" {
		t.Fatalf("unexpected upstream fixture seal: %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(mustHex(verifierKeyHex))); got != "7d5401f6af5e97bd364002b55c6f607f2438aded4e342d1a558b275ceabaa68c" {
		t.Fatalf("unexpected raw verifier key digest: %s", got)
	}
	claim := successClaim(imageID, journal)
	if got := fmt.Sprintf("%x", claim); got != "02e217ec3932749a48182e61b15d5145998f339a496225cc6b4f5c01d29992be" {
		t.Fatalf("incorrect reconstructed successful claim: %s", got)
	}
	want := [5]string{
		"122454446009092889111564049266976489190",
		"38990139598553237306463054510761161097",
		"92139208072254192114874321104067355138",
		"253314514387484668627264477858834386841",
		"4867518560574799428715477036611075029821757930133704723640824519674718880222",
	}
	for i, input := range publicSignals(claim) {
		if input.String() != want[i] {
			t.Fatalf("public input %d: got %s want %s", i, input, want[i])
		}
	}
	if err := VerifyFixture(seal, journal); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsChangedJournalImageAndProof(t *testing.T) {
	seal := mustHex(fixtureSealHex)
	journal := mustHex(fixtureJournalHex)
	changedJournal := slices.Clone(journal)
	changedJournal[0] ^= 1
	changedImage := imageID
	changedImage[0] ^= 1

	// Negate the proof's A coordinate as a whole group element. It remains
	// canonical and in the correct subgroup so rejection exercises pairing.
	changedProof := slices.Clone(seal)
	var a bn254.G1Affine
	if err := decodePoint(&a, changedProof[4:4+g1Bytes]); err != nil {
		t.Fatal(err)
	}
	a.Neg(&a)
	encoded := a.RawBytes()
	copy(changedProof[4:4+g1Bytes], encoded[:])

	for _, variant := range []struct {
		name          string
		seal, journal []byte
		image         [32]byte
	}{
		{"journal", seal, changedJournal, imageID},
		{"image", seal, journal, changedImage},
		{"proof", changedProof, journal, imageID},
	} {
		t.Run(variant.name, func(t *testing.T) {
			err := verifyReceipt(variant.seal, variant.image, variant.journal)
			if !errors.Is(err, invalidProof) {
				t.Fatalf("expected the pairing to reject changed %s, got %v", variant.name, err)
			}
		})
	}
}

func TestRejectsOtherSelectorsAndInvalidWire(t *testing.T) {
	seal := mustHex(fixtureSealHex)
	journal := mustHex(fixtureJournalHex)
	stopped := slices.Clone(seal)
	copy(stopped, mustHex("8b38038c")) // Superseded v3.1.0 selector from the upstream advisory.
	zeroA := slices.Clone(seal)
	clear(zeroA[4 : 4+g1Bytes])

	for _, variant := range []struct {
		name string
		seal []byte
	}{
		{"stopped selector", stopped},
		{"truncated seal", seal[:len(seal)-1]},
		{"trailing byte", append(slices.Clone(seal), 0)},
		{"point at infinity", zeroA},
	} {
		t.Run(variant.name, func(t *testing.T) {
			if err := VerifyFixture(variant.seal, journal); err == nil {
				t.Fatalf("accepted %s", variant.name)
			}
		})
	}
}

// Exact bytes from v3.1.0 contracts/test/TestReceiptV3_1.sol.
const fixtureJournalHex = "6a75737420612073696d706c652072656365697074"
const fixtureSealHex = "e71e662021a0c81a5cc1c5cddabc3eefe6a3841315ad1a1cd74da3f34db1db91" +
	"d01240a70b220d069e774da52f06c0d0ca166b219f0e1b0548a08270fa88f5e7" +
	"1a55bb2911fba8d9c52968295894f9b6e1804afcda16b66956ad973a290cb8d6" +
	"736813502b336b4ec0382ab1a7508781f3e1a8d7ea73d4491382cae39ec9f14a" +
	"ff07f53623bc5d3d6a718a686588bd6027b1713110031c85fa34117a4fed94d9" +
	"8a41fe8e0bcf572d3389eedcc34ec00bd1aa571b0bcaa80af13b30bf3cb26741" +
	"e56deabb23d1abf7efdfba3f55523687ce10ef220c8d6d879f2e9161684f044e" +
	"6e3597a2087d050b687d2242476dde08f789d726635f51ccd6fc216091297f0b" +
	"7b416a6a"
