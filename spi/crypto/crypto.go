/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package crypto contains the Crypto interface to be used by the framework.
// It will be created via Options creation in pkg/framework/context.Provider.
// BBS+ signature scheme is not included in the main Crypto interface.
// It is defined separately under the primitive sub-package including its implementation which should not be referenced
// directly. It is accessible via the framework's KMS BBS+ keys and tinkcrypto's bbs package's Signer and Verifier
// primitives or via webkms for remote KMS BBS+ signing.
package crypto

// Crypto interface provides all crypto operations needed in the Aries framework.
type Crypto interface {
	// Encrypt will encrypt msg and aad using a matching AEAD primitive in kh key handle of a public key
	// returns:
	// 		cipherText in []byte
	//		nonce in []byte
	//		error in case of errors during encryption
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)
	// Decrypt will decrypt cipher with aad and given nonce using a matching AEAD primitive in kh key handle of a
	// private key
	// returns:
	//		plainText in []byte
	//		error in case of errors
	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)
	// Sign will sign msg using a matching signature primitive in kh key handle of a private key
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte, kh interface{}) ([]byte, error)
	// Verify will verify a signature for the given msg using a matching signature primitive in kh key handle of
	// a public key
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(signature, msg []byte, kh interface{}) error
	// ComputeMAC computes message authentication code (MAC) for code data
	// using a matching MAC primitive in kh key handle
	ComputeMAC(data []byte, kh interface{}) ([]byte, error)
	// VerifyMAC determines if mac is a correct authentication code (MAC) for data
	// using a matching MAC primitive in kh key handle and returns nil if so, otherwise it returns an error.
	VerifyMAC(mac, data []byte, kh interface{}) error
	// WrapKey will execute key wrapping of cek using apu, apv and recipient public key 'recPubKey'.
	// 'opts' allows setting the optional sender key handle using WithSender() option and the an authentication tag
	// using WithTag() option. These allow ECDH-1PU key unwrapping (aka Authcrypt).
	// The absence of these options uses ECDH-ES key wrapping (aka Anoncrypt). Another option that can
	// be used is WithXC20PKW() to instruct the WrapKey to use XC20P key wrapping instead of the default A256GCM.
	// returns:
	// 		RecipientWrappedKey containing the wrapped cek value
	// 		error in case of errors
	WrapKey(cek, apu, apv []byte, recPubKey *PublicKey,
		opts ...WrapKeyOpts) (*RecipientWrappedKey, error)
	// UnwrapKey unwraps a key in recWK using recipient private key kh.
	// 'opts' allows setting the optional sender key handle using WithSender() option and the an authentication tag
	// using WithTag() option. These allow ECDH-1PU key unwrapping (aka Authcrypt).
	// The absence of these options uses ECDH-ES key unwrapping (aka Anoncrypt). There is no need to
	// use WithXC20PKW() for UnwrapKey since the function will use the wrapping algorithm based on recWK.Alg.
	// returns:
	// 		unwrapped key in raw bytes
	// 		error in case of errors
	UnwrapKey(recWK *RecipientWrappedKey, kh interface{}, opts ...WrapKeyOpts) ([]byte, error)
	// SignMulti will create a signature of messages using a matching signing primitive found in kh key handle of a
	// private key.
	// returns:
	// 		signature in []byte
	//		error in case of errors
	SignMulti(messages [][]byte, kh interface{}) ([]byte, error)
	// VerifyMulti will verify a signature of messages using a matching signing primitive found in kh key handle of a
	// public key.
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	VerifyMulti(messages [][]byte, signature []byte, kh interface{}) error
	// VerifyProof will verify a signature proof (generated e.g. by Verifier's DeriveProof() call) for revealedMessages
	// using a matching signing primitive found in kh key handle of a public key.
	// returns:
	// 		error in case of errors or nil if signature proof verification was successful
	VerifyProof(revealedMessages [][]byte, proof, nonce []byte, kh interface{}) error
	// DeriveProof will create a signature proof for a list of revealed messages using BBS signature (can be built using
	// a Signer's SignMulti() call) and a matching signing primitive found in kh key handle of a public key.
	// returns:
	// 		signature proof in []byte
	//		error in case of errors
	DeriveProof(messages [][]byte, bbsSignature, nonce []byte, revealedIndexes []int, kh interface{}) ([]byte, error)
	// Blind will blind provided values and add blinded data realted to the key in kh
	// returns:
	// 		blinded values in []byte
	//		error in case of errors
	Blind(kh interface{}, values ...map[string]interface{}) ([][]byte, error)
	// GetCorrectnessProof will return correctness proof for a public key handle
	// returns:
	// 		correctness proof in []byte
	//		error in case of errors
	GetCorrectnessProof(kh interface{}) ([]byte, error)
	// SignWithSecrets will generate a signature and related correctness proof
	// for the provided values using secrets and related DID
	// returns:
	// 		signature in []byte
	// 		correctness proof in []byte
	//		error in case of errors
	SignWithSecrets(kh interface{}, values map[string]interface{},
		secrets []byte, correctnessProof []byte, nonces [][]byte, did string) ([]byte, []byte, error)
}

// RecipientWrappedKey contains recipient key material required to unwrap CEK.
type RecipientWrappedKey struct {
	KID          string    `json:"kid,omitempty"`
	EncryptedCEK []byte    `json:"encryptedcek,omitempty"`
	EPK          PublicKey `json:"epk,omitempty"`
	Alg          string    `json:"alg,omitempty"`
	APU          []byte    `json:"apu,omitempty"`
	APV          []byte    `json:"apv,omitempty"`
}

// PublicKey mainly to exchange EPK in RecipientWrappedKey.
type PublicKey struct {
	KID   string `json:"kid,omitempty"`
	X     []byte `json:"x,omitempty"`
	Y     []byte `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

// PrivateKey mainly used to exchange ephemeral private key in JWE encrypter.
type PrivateKey struct {
	PublicKey PublicKey `json:"pubKey,omitempty"`
	D         []byte    `json:"d,omitempty"`
}
