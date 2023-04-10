/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package composite

// package composite provides the core crypto composite primitives such as ECDH-ES and ECDH-1PU to be used by JWE crypto

// EncryptedData represents the Encryption's output data as a result of ECDHEncrypt.Encrypt(pt, aad) call
// The user of the primitive must unmarshal the result and build their own ECDH-ES/1PU compliant message (ie JWE msg).
type EncryptedData struct {
	Ciphertext []byte `json:"ciphertext,omitempty"`
	IV         []byte `json:"iv,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
}
