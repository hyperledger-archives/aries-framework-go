/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

// package crypto contains the Crypto interface to be used by the framework.
// it will be created via Options creation in pkg/framework/context.Provider

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
	// 'opts' allows setting the option sender key handle using WithSender() option. It allows ECDH-1PU key wrapping
	// (aka Authcrypt). The absence of this option uses ECDH-ES key wrapping (aka Anoncrypt).
	// returns:
	// 		RecipientWrappedKey containing the wrapped cek value
	// 		error in case of errors
	WrapKey(cek, apu, apv []byte, recPubKey *PublicKey,
		opts ...WrapKeyOpts) (*RecipientWrappedKey, error)

	// UnwrapKey unwraps a key in recWK using recipient private key kh.
	// 'opts' allows setting the option sender key handle using WithSender() option. It allows ECDH-1PU key unwrapping
	// (aka Authcrypt). The absence of this option uses ECDH-ES key unwrapping (aka Anoncrypt).
	// returns:
	// 		unwrapped key in raw bytes
	// 		error in case of errors
	UnwrapKey(recWK *RecipientWrappedKey, kh interface{}, opts ...WrapKeyOpts) ([]byte, error)
}

// DefKeySize is the default key size for crypto primitives.
const DefKeySize = 32

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
