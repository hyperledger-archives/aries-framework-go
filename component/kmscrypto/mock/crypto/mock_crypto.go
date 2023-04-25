/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package crypto

import (
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
)

// SignFunc mocks Crypto's Sign() function, it's useful for executing custom signing with the help of SignKey.
type SignFunc func([]byte, interface{}) ([]byte, error)

// BBSSignFunc mocks Crypto's BBSSign() function, it's useful for executing custom BBS+ signing with the help of
// Signing private Key.
type BBSSignFunc func([][]byte, interface{}) ([]byte, error)

// DeriveProofFunc mocks Crypto's DeriveProofFunc() function, it's useful for executing custom BBS+ signing with the
// help of Signing public Key.
type DeriveProofFunc func([][]byte, []byte, []byte, []int, interface{}) ([]byte, error)

// Crypto mock.
type Crypto struct {
	EncryptValue             []byte
	EncryptNonceValue        []byte
	EncryptErr               error
	DecryptValue             []byte
	DecryptErr               error
	SignValue                []byte
	SignKey                  []byte
	SignFn                   SignFunc
	SignErr                  error
	VerifyErr                error
	ComputeMACValue          []byte
	ComputeMACErr            error
	VerifyMACErr             error
	WrapValue                *cryptoapi.RecipientWrappedKey
	WrapError                error
	UnwrapValue              []byte
	UnwrapError              error
	BBSSignValue             []byte
	BBSSignKey               []byte
	BBSSignFn                BBSSignFunc
	BBSSignErr               error
	BBSVerifyErr             error
	VerifyProofErr           error
	DeriveProofValue         []byte
	DeriveProofKey           []byte
	DeriveProofFn            DeriveProofFunc
	DeriveProofError         error
	BlindValue               [][]byte
	BlindError               error
	GetCorrectnessProofValue []byte
	GetCorrectnessProofError error
	SignWithSecretsValue     []byte
	SignWithSecretsProof     []byte
	SignWithSecretsError     error
}

// Encrypt returns mocked values and a mocked error.
func (c *Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	return c.EncryptValue, c.EncryptNonceValue, c.EncryptErr
}

// Decrypt returns a mocked value and a mocked error.
func (c *Crypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	return c.DecryptValue, c.DecryptErr
}

// Sign returns a mocked value and a mocked error.
func (c *Crypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	if c.SignFn != nil {
		return c.SignFn(msg, c.SignKey)
	}

	return c.SignValue, c.SignErr
}

// Verify returns a mocked value.
func (c *Crypto) Verify(signature, msg []byte, kh interface{}) error {
	return c.VerifyErr
}

// ComputeMAC returns a mocked value and a mocked error.
func (c *Crypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	return c.ComputeMACValue, c.ComputeMACErr
}

// VerifyMAC returns a mocked value.
func (c *Crypto) VerifyMAC(mac, data []byte, kh interface{}) error {
	return c.VerifyMACErr
}

// WrapKey returns a mocked value.
func (c *Crypto) WrapKey(cek, apu, apv []byte, recPubKey *cryptoapi.PublicKey,
	wrapKeyOpts ...cryptoapi.WrapKeyOpts) (*cryptoapi.RecipientWrappedKey, error) {
	return c.WrapValue, c.WrapError
}

// UnwrapKey returns a mocked value.
func (c *Crypto) UnwrapKey(recWK *cryptoapi.RecipientWrappedKey, kh interface{},
	wrapKeyOpts ...cryptoapi.WrapKeyOpts) ([]byte, error) {
	return c.UnwrapValue, c.UnwrapError
}

// SignMulti returns a mocked BBS+ signature value and a mocked error.
func (c *Crypto) SignMulti(messages [][]byte, kh interface{}) ([]byte, error) {
	if c.BBSSignFn != nil {
		return c.BBSSignFn(messages, c.BBSSignKey)
	}

	return c.BBSSignValue, c.BBSSignErr
}

// VerifyMulti returns a mocked BBS+ verify result.
// returns:
//
//	error in case of errors or nil if signature verification was successful
func (c *Crypto) VerifyMulti(messages [][]byte, signature []byte, kh interface{}) error {
	return c.BBSVerifyErr
}

// VerifyProof returns a mocked BBS+ verify signature proof result.
// returns:
//
//	error in case of errors or nil if signature proof verification was successful
func (c *Crypto) VerifyProof(revealedMessages [][]byte, proof, nonce []byte, signerPubKH interface{}) error {
	return c.VerifyProofErr
}

// DeriveProof returns a mocked BBS+ signature proof value and a mocked error.
// returns:
//
//	signature proof in []byte
//	error in case of errors
func (c *Crypto) DeriveProof(messages [][]byte, bbsSignature, nonce []byte, revealedIndexes []int,
	signerPubKH interface{}) ([]byte, error) {
	if c.DeriveProofFn != nil {
		return c.DeriveProofFn(messages, bbsSignature, nonce, revealedIndexes, c.DeriveProofKey)
	}

	return c.DeriveProofValue, c.DeriveProofError
}

// Blind returns a mocked blinded vals and a mocked error.
// returns:
//
//	blinded values in []byte
//	error in case of errors
func (c *Crypto) Blind(kh interface{}, values ...map[string]interface{}) ([][]byte, error) {
	return c.BlindValue, c.BlindError
}

// GetCorrectnessProof returns a mocked correctness proof value and a mocked error.
// returns:
//
//	correctness proof in []byte
//	error in case of errors
func (c *Crypto) GetCorrectnessProof(kh interface{}) ([]byte, error) {
	return c.GetCorrectnessProofValue, c.GetCorrectnessProofError
}

// SignWithSecrets returns the mocked signature and correctness proof values and a mocked error.
// returns:
//
//	signature in []byte
//	correctness proof in []byte
//	error in case of errors
func (c *Crypto) SignWithSecrets(kh interface{}, values map[string]interface{},
	secrets []byte, correctnessProof []byte, nonces [][]byte, did string) ([]byte, []byte, error) {
	return c.SignWithSecretsValue, c.SignWithSecretsProof, c.SignWithSecretsError
}
