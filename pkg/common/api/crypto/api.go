/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

// package Crypto contains the consolidated Crypto interface to be used by the framework.
// it will be created via Options creation of pkg/framework/provider/crypto (implementation of
// pkg/framework/spi/crypto)

// Crypto interface provides all crypto operations needed in the Aries framework
type Crypto interface {
	// Encrypt will encrypt msg and aad using a matching AEAD primitive in kh key handle
	// returns:
	// 		cipherText in []byte
	//		nonce in []byte
	//		error in case of errors during encryption
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)
	// Decrypt will decrypt cipher with aad and given nonce using a matching AEAD primitive in kh key handle
	// returns:
	//		plainText in []byte
	//		error in case of errors
	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)
	// Sign will sign msg using a matching signature primitive in kh key handle
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte, kh interface{}) ([]byte, error)
	// Verify will verify a signature for the given msg using a matching signature primitive in kh key handle
	// returns:
	// 		error in case of errors or nil if signature verification was successful
	Verify(signature, msg []byte, kh interface{}) error
}
