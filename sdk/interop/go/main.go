package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/bsv-blockchain/go-sdk/script/interpreter"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-wallet-toolbox/pkg/brc29"
)

type transactionPair struct {
	Funding string
	Signed  string
	Txid    string
	Vout    uint32
	Project string
	Release string
}

type payment struct {
	transactionPair
	SenderTestKey      string
	RecipientPublicKey string
	DerivationPrefix   string
	DerivationSuffix   string
}

func readFixture[T any](path string) (T, error) {
	var fixture T
	raw, err := os.ReadFile(path)
	if err != nil {
		return fixture, err
	}
	err = json.Unmarshal(raw, &fixture)
	return fixture, err
}

func decodePayment(fixture transactionPair) (*transaction.Transaction, *transaction.Transaction, error) {
	funding, err := transaction.NewTransactionFromHex(fixture.Funding)
	if err != nil {
		return nil, nil, err
	}
	signed, err := transaction.NewTransactionFromHex(fixture.Signed)
	if err != nil {
		return nil, nil, err
	}
	if funding.Hex() != fixture.Funding || signed.Hex() != fixture.Signed || signed.TxID().String() != fixture.Txid {
		return nil, nil, errors.New("transaction did not round-trip")
	}
	if len(signed.Inputs) != 1 || uint64(fixture.Vout) >= uint64(len(funding.Outputs)) {
		return nil, nil, errors.New("expected a single input and a matching funding output")
	}
	input := signed.Inputs[0]
	if input.SourceTXID.String() != funding.TxID().String() || input.SourceTxOutIndex != fixture.Vout {
		return nil, nil, errors.New("payment does not spend the funding outpoint")
	}
	return funding, signed, nil
}

func verify(fixture payment) error {
	funding, signed, err := decodePayment(fixture.transactionPair)
	if err != nil {
		return err
	}
	keyID := brc29.KeyID{
		DerivationPrefix: fixture.DerivationPrefix,
		DerivationSuffix: fixture.DerivationSuffix,
	}
	lock, err := brc29.LockForCounterparty(brc29.PrivHex(fixture.SenderTestKey), keyID,
		brc29.PubHex(fixture.RecipientPublicKey))
	if err != nil {
		return err
	}
	output := funding.Outputs[fixture.Vout]
	if lock.String() != output.LockingScript.String() {
		return errors.New("derived BRC-29 script differs from the funding script")
	}
	if err := interpreter.NewEngine().Execute(
		interpreter.WithTx(signed, 0, output), interpreter.WithAfterGenesis(),
	); err != nil {
		return fmt.Errorf("validate payment: %w", err)
	}
	return nil
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: go run . BRC29_FIXTURE PROJECT_FIXTURES")
	}
	native, err := readFixture[payment](os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := verify(native); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Go SDK and Wallet Toolbox:", native.Txid)

	projects, err := readFixture[[]transactionPair](os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	for _, project := range projects {
		if _, _, err := decodePayment(project); err != nil {
			log.Fatalf("%s v%s: %v", project.Project, project.Release, err)
		}
	}
	fmt.Printf("Go SDK: %d project transactions round-tripped\n", len(projects))
}
