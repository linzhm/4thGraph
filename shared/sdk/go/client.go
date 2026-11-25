// Package sdklocal provides local reference-backed BSV wallet SDK operations.
package sdklocal

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
)

type Config struct {
	Python string
	Bridge string
}

type Recognition struct {
	Template     string `json:"template"`
	OwnerHash160 string `json:"ownerHash160,omitempty"`
}

type Output struct {
	ValueSats string `json:"valueSats"`
	Script    string `json:"script"`
}

type SigningOptions struct {
	Funding          string `json:"funding"`
	Index            uint32 `json:"index"`
	PublicKey        string `json:"publicKey"`
	Sighash          *uint8 `json:"sighash,omitempty"`
	ChronicleActive  bool   `json:"chronicleActive,omitempty"`
	CompressOTDA     bool   `json:"compressOtda,omitempty"`
	SignerIdentifier string `json:"signerIdentifier,omitempty"`
}

type Spend struct {
	SigningOptions
	Transaction string `json:"transaction"`
}

type Payment struct {
	SigningOptions
	Outputs []Output `json:"outputs"`
	FeeSats string   `json:"feeSats"`
}

// Signer receives digest bytes, and for SM2 also the user ID. It returns signature bytes.
type Signer func(arguments ...[]byte) ([]byte, error)

type Client struct {
	project, python, bridge string
}

func New(project string, config Config) *Client {
	if config.Python == "" {
		config.Python = "python3"
	}
	return &Client{project, config.Python, config.Bridge}
}

func (c *Client) call(ctx context.Context, operation string, options any, arguments []string, signature string, result any) error {
	message := struct {
		Protocol  int      `json:"protocol"`
		Project   string   `json:"project"`
		Operation string   `json:"operation"`
		Request   any      `json:"request"`
		Arguments []string `json:"arguments,omitempty"`
		Signature string   `json:"signature,omitempty"`
	}{1, c.project, operation, options, arguments, signature}
	input, err := json.Marshal(message)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, c.python, c.bridge)
	command.Stdin = bytes.NewReader(input)
	stdout, err := command.Output()
	if err != nil {
		return fmt.Errorf("local SDK bridge: %w", err)
	}
	var reply struct {
		OK     bool            `json:"ok"`
		Error  string          `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(stdout, &reply); err != nil {
		return fmt.Errorf("invalid SDK bridge response: %w", err)
	}
	if !reply.OK {
		return errors.New(reply.Error)
	}
	return json.Unmarshal(reply.Result, result)
}

func (c *Client) Lock(ctx context.Context, publicKey, profile string) (string, error) {
	request := map[string]string{"publicKey": publicKey}
	if profile != "" {
		request["profile"] = profile
	}
	var script string
	err := c.call(ctx, "lock", request, nil, "", &script)
	return script, err
}

func (c *Client) Recognize(ctx context.Context, script, publicKey string) (*Recognition, error) {
	request := map[string]string{"script": script}
	if publicKey != "" {
		request["publicKey"] = publicKey
	}
	var result *Recognition
	err := c.call(ctx, "recognize", request, nil, "", &result)
	return result, err
}

func (c *Client) LockForOwner(ctx context.Context, ownerHash160 string) (string, error) {
	var script string
	err := c.call(ctx, "lockOwner", map[string]string{"ownerHash160": ownerHash160}, nil, "", &script)
	return script, err
}

func (c *Client) sign(ctx context.Context, options any, signer Signer) (string, error) {
	if signer == nil {
		return "", errors.New("external signer is required")
	}
	snapshot, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	request := json.RawMessage(snapshot)
	var arguments []string
	if err := c.call(ctx, "prepare", request, nil, "", &arguments); err != nil {
		return "", err
	}
	bytes := make([][]byte, len(arguments))
	for index, argument := range arguments {
		value, err := hex.DecodeString(argument)
		if err != nil {
			return "", err
		}
		bytes[index] = value
	}
	signature, err := signer(bytes...)
	if err != nil {
		return "", err
	}
	var result string
	err = c.call(ctx, "finish", request, arguments, hex.EncodeToString(signature), &result)
	return result, err
}

func (c *Client) SignSpend(ctx context.Context, request Spend, signer Signer) (string, error) {
	return c.sign(ctx, request, signer)
}

func (c *Client) SignPayment(ctx context.Context, request Payment, signer Signer) (string, error) {
	return c.sign(ctx, request, signer)
}

// Prevout identifies an output the wallet has authenticated in its chain view.
type Prevout struct {
	Output
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type LockRequest struct {
	PublicKey    string `json:"publicKey,omitempty"`
	OwnerHash160 string `json:"ownerHash160,omitempty"`
	ValueSats    string `json:"valueSats,omitempty"`
}

type RecognizeRequest struct {
	Script    string `json:"script"`
	PublicKey string `json:"publicKey,omitempty"`
	ValueSats string `json:"valueSats,omitempty"`
}

type WalletRecognition struct {
	Recognition
	Project            string `json:"project"`
	PublicKey          string `json:"publicKey,omitempty"`
	TargetTemplate     string `json:"targetTemplate,omitempty"`
	TargetScriptSHA256 string `json:"targetScriptSha256,omitempty"`
	TargetTxOutHash256 string `json:"targetTxOutHash256,omitempty"`
}

type WalletSigningOptions struct {
	PublicKey        string `json:"publicKey"`
	Sighash          *uint8 `json:"sighash,omitempty"`
	ChronicleActive  bool   `json:"chronicleActive,omitempty"`
	CompressOTDA     bool   `json:"compressOtda,omitempty"`
	SignerIdentifier string `json:"signerIdentifier,omitempty"`
	HistoryPath      string `json:"historyPath,omitempty"`
	SignMessage      bool   `json:"signMessage,omitempty"`
}

type WalletPayment struct {
	WalletSigningOptions
	Prevout Prevout  `json:"prevout"`
	Outputs []Output `json:"outputs"`
	FeeSats string   `json:"feeSats"`
}

type WalletInput struct {
	WalletSigningOptions
	Prevout     Prevout `json:"prevout"`
	Transaction string  `json:"transaction"`
	InputIndex  uint32  `json:"inputIndex"`
}

type Activation struct {
	Prevout         Prevout `json:"prevout"`
	Transaction     string  `json:"transaction"`
	InputIndex      uint32  `json:"inputIndex"`
	Sighash         *uint8  `json:"sighash,omitempty"`
	ChronicleActive bool    `json:"chronicleActive,omitempty"`
}

type SigningRequest struct {
	Algorithm       string `json:"algorithm"`
	PayloadKind     string `json:"payloadKind"`
	SignatureFormat string `json:"signatureFormat"`
	Sighash         uint8  `json:"sighash"`
	Payload         []byte `json:"-"`
	UserID          []byte `json:"-"`
}

type WalletSigner func(SigningRequest) ([]byte, error)

type WalletClient struct {
	bridge   *Client
	template string
}

func NewWallet(project string, config Config, template string) *WalletClient {
	return &WalletClient{bridge: New(project, config), template: template}
}

func (c *WalletClient) PrevoutFromFunding(ctx context.Context, funding string, vout uint32) (Prevout, error) {
	request := struct {
		Funding string `json:"funding"`
		Vout    uint32 `json:"vout"`
	}{funding, vout}
	var result Prevout
	err := c.bridge.call(ctx, "prevoutFromFunding", request, nil, "", &result)
	return result, err
}

func (c *WalletClient) CreateLock(ctx context.Context, request LockRequest) (string, error) {
	options := struct {
		LockRequest
		Template string `json:"template,omitempty"`
	}{request, c.template}
	var result string
	err := c.bridge.call(ctx, "createLock", options, nil, "", &result)
	return result, err
}

func (c *WalletClient) Recognize(ctx context.Context, request RecognizeRequest) (*WalletRecognition, error) {
	var result *WalletRecognition
	err := c.bridge.call(ctx, "recognizeLock", request, nil, "", &result)
	return result, err
}

func (c *WalletClient) sign(ctx context.Context, options any, signer WalletSigner) (string, error) {
	if signer == nil {
		return "", errors.New("external signer is required")
	}
	snapshot, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	request := json.RawMessage(snapshot)
	var prepared struct {
		SigningRequest
		Arguments []string `json:"arguments"`
	}
	if err := c.bridge.call(ctx, "prepareWallet", request, nil, "", &prepared); err != nil {
		return "", err
	}
	if len(prepared.Arguments) < 1 || len(prepared.Arguments) > 2 {
		return "", errors.New("invalid signing request arguments")
	}
	prepared.Payload, err = hex.DecodeString(prepared.Arguments[0])
	if err != nil {
		return "", err
	}
	if len(prepared.Arguments) == 2 {
		prepared.UserID, err = hex.DecodeString(prepared.Arguments[1])
		if err != nil {
			return "", err
		}
	}
	signature, err := signer(prepared.SigningRequest)
	if err != nil {
		return "", err
	}
	var result string
	err = c.bridge.call(ctx, "finishWallet", request, prepared.Arguments, hex.EncodeToString(signature), &result)
	return result, err
}

func (c *WalletClient) SignPayment(ctx context.Context, request WalletPayment, signer WalletSigner) (string, error) {
	return c.sign(ctx, request, signer)
}

func (c *WalletClient) SignInput(ctx context.Context, request WalletInput, signer WalletSigner) (string, error) {
	return c.sign(ctx, request, signer)
}

func (c *WalletClient) Activate(ctx context.Context, request Activation) (string, error) {
	var result string
	err := c.bridge.call(ctx, "activate", request, nil, "", &result)
	return result, err
}
