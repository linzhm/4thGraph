package wots

import sdk "github.com/linzhm/bsv-script-lab/shared/sdk/go"

type Config = sdk.Config
type SigningOptions = sdk.SigningOptions
type Output = sdk.Output
type Payment = sdk.Payment
type Spend = sdk.Spend
type Recognition = sdk.Recognition
type Signer = sdk.Signer
type Client = sdk.Client

func New(config Config) *Client {
	return sdk.New("wots-plus", config)
}
