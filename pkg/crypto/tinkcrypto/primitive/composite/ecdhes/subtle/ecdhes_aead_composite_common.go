/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

// package subtle provides the core crypto primitives to be used by composite primitives. It is intended for internal
// use only.

// EncryptedData represents the Encryption's output data as a result of ECDHESEncrypt.Encrypt(pt, aad) call
// The user of the primitive must unmarshal the result and build their own ECDH-ES compliant message (ie JWE msg)
type EncryptedData struct {
	EncAlg     string                 `json:"encalg,omitempty"`
	Ciphertext []byte                 `json:"ciphertext,omitempty"`
	IV         []byte                 `json:"iv,omitempty"`
	Tag        []byte                 `json:"tag,omitempty"`
	Recipients []*RecipientWrappedKey `json:"recipients,omitempty"`
	// SingleRecipientAAD is the result of an AAD update using a single recipient JWE envelope with recipient headers.
	// The JWE encrypter in this framework rebuilds this AAD value when building/parsing the JWE envelope. It does not
	// use this field. It is added here to provide access to the updated AAD for single recipient encryption use by
	// external users of this crypto primitive.
	SingleRecipientAAD []byte `json:"singlerecipientaad,omitempty"`
}

// RecipientWrappedKey contains recipient key material required to unwrap CEK
type RecipientWrappedKey struct {
	KID          string    `json:"kid,omitempty"`
	EncryptedCEK []byte    `json:"encryptedcek,omitempty"`
	EPK          PublicKey `json:"epk,omitempty"`
	Alg          string    `json:"alg,omitempty"`
}

// PublicKey mainly to exchange EPK in RecipientWrappedKey
type PublicKey struct {
	KID   string `json:"kid,omitempty"`
	X     []byte `json:"x,omitempty"`
	Y     []byte `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}
