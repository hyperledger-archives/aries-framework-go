/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

// EncryptedData represents the Encryption's output data as a result of ECDHESEncrypt.Encrypt(pt, aad) call
// The user of the primitive must unmarshal the result and build their own ECDH-ES compliant message (ie JWE msg)
type EncryptedData struct {
	EncAlg     string                 `json:"EncAlg,omitempty"`
	Ciphertext []byte                 `json:"Ciphertext,omitempty"`
	IV         []byte                 `json:"IV,omitempty"`
	Tag        []byte                 `json:"Tag,omitempty"`
	Recipients []*RecipientWrappedKey `json:"Recipients,omitempty"`
}

// RecipientWrappedKey contains recipient key material required to unwrap CEK
type RecipientWrappedKey struct {
	EncryptedCEK []byte      `json:"EncryptedCEK,omitempty"`
	EPK          ECPublicKey `json:"EPK,omitempty"`
	Alg          string      `json:"Alg,omitempty"`
}

// ECPublicKey mainly to exchange EPK in RecipientWrappedKey
type ECPublicKey struct {
	X     []byte `json:"X,omitempty"`
	Y     []byte `json:"Y,omitempty"`
	Curve string `json:"curve,omitempty"`
}
