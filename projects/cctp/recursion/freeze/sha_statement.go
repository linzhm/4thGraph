package freeze

import "github.com/consensys/gnark/frontend"

// AssertSHA256dStatement checks byte ranges and SHA256d(domain || payload).
// The digest is represented by two ordered big-endian uint128 public values.
// The bitwise hash imposes no lookup or commitment constraints.
func AssertSHA256dStatement(api frontend.API, domain string, payload []frontend.Variable, public [2]frontend.Variable) {
	message := make([]shaOctet, 0, len(domain)+len(payload))
	for _, value := range []byte(domain) {
		message = append(message, octetBits(value))
	}
	for _, value := range payload {
		message = append(message, shaOctet(api.ToBinary(value, 8)))
	}

	digest := sha256Bits(api, sha256Bits(api, message))
	for i, expected := range public {
		limb := frontend.Variable(0)
		for _, octet := range digest[i*16 : (i+1)*16] {
			limb = api.Add(api.Mul(limb, 256), api.FromBinary(octet[:]...))
		}
		api.AssertIsEqual(expected, limb)
	}
}
