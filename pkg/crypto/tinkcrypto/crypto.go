/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package tinkcrypto provides the default implementation of the
// common pkg/common/api/crypto.Crypto interface and the SPI pkg/framework/aries.crypto interface
//
// It uses github.com/tink/go crypto primitives
package tinkcrypto

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/tink/go/aead"
	aeadsubtle "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"golang.org/x/crypto/chacha20poly1305"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
)

const (
	// ECDHESA256KWAlg is the ECDH-ES with AES-GCM 256 key wrapping algorithm.
	ECDHESA256KWAlg = "ECDH-ES+A256KW"
	// ECDH1PUA256KWAlg is the ECDH-1PU with AES-GCM 256 key wrapping algorithm.
	ECDH1PUA256KWAlg = "ECDH-1PU+A256KW"
)

var errBadKeyHandleFormat = errors.New("bad key handle format")

// Package tinkcrypto includes the default implementation of pkg/crypto. It uses Tink for executing crypto primitives
// and will be built as a framework option. It represents the main crypto service in the framework. `kh interface{}`
// arguments in this implementation represent Tink's `*keyset.Handle`, using this type provides easy integration with
// Tink and the default KMS service.

// Crypto is the default Crypto SPI implementation using Tink.
type Crypto struct {
	kw keyWrapper
}

// New creates a new Crypto instance.
func New() (*Crypto, error) {
	return &Crypto{kw: &keyWrapperSupport{}}, nil
}

// Encrypt will encrypt msg using the implementation's corresponding encryption key and primitive in kh of a public key.
func (t *Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, nil, errBadKeyHandleFormat
	}

	ps, err := keyHandle.Primitives()
	if err != nil {
		return nil, nil, fmt.Errorf("get primitives: %w", err)
	}

	a, err := aead.New(keyHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("create new aead: %w", err)
	}

	ct, err := a.Encrypt(msg, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt msg: %w", err)
	}

	// Tink appends a key prefix + nonce to ciphertext, let's remove them to get the raw ciphertext
	ivSize := nonceSize(ps)
	prefixLength := len(ps.Primary.Prefix)
	cipherText := ct[prefixLength+ivSize:]
	nonce := ct[prefixLength : prefixLength+ivSize]

	return cipherText, nonce, nil
}

func nonceSize(ps *primitiveset.PrimitiveSet) int {
	var ivSize int
	// AESGCM and XChacha20Poly1305 nonce sizes supported only for now
	switch ps.Primary.Primitive.(type) {
	case *aeadsubtle.XChaCha20Poly1305:
		ivSize = chacha20poly1305.NonceSizeX
	case *aeadsubtle.AESGCM:
		ivSize = aeadsubtle.AESGCMIVSize
	default:
		ivSize = aeadsubtle.AESGCMIVSize
	}

	return ivSize
}

// Decrypt will decrypt cipher using the implementation's corresponding encryption key referenced by kh of
// a private key.
func (t *Crypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	ps, err := keyHandle.Primitives()
	if err != nil {
		return nil, fmt.Errorf("get primitives: %w", err)
	}

	a, err := aead.New(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new aead: %w", err)
	}

	// since Tink expects the key prefix + nonce as the ciphertext prefix, prepend them prior to calling its Decrypt()
	ct := make([]byte, 0, len(ps.Primary.Prefix)+len(nonce)+len(cipher))
	ct = append(ct, ps.Primary.Prefix...)
	ct = append(ct, nonce...)
	ct = append(ct, cipher...)

	pt, err := a.Decrypt(ct, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt cipher: %w", err)
	}

	return pt, nil
}

// Sign will sign msg using the implementation's corresponding signing key referenced by kh of a private key.
func (t *Crypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	signer, err := signature.NewSigner(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new signer: %w", err)
	}

	s, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("sign msg: %w", err)
	}

	return s, nil
}

// Verify will verify sig signature of msg using the implementation's corresponding signing key referenced by kh of
// a public key.
func (t *Crypto) Verify(sig, msg []byte, kh interface{}) error {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return errBadKeyHandleFormat
	}

	verifier, err := signature.NewVerifier(keyHandle)
	if err != nil {
		return fmt.Errorf("create new verifier: %w", err)
	}

	err = verifier.Verify(sig, msg)
	if err != nil {
		err = fmt.Errorf("verify msg: %w", err)
	}

	return err
}

// ComputeMAC computes message authentication code (MAC) for code data
// using a matching MAC primitive in kh key handle.
func (t *Crypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	macPrimitive, err := mac.New(keyHandle)
	if err != nil {
		return nil, err
	}

	return macPrimitive.ComputeMAC(data)
}

// VerifyMAC determines if mac is a correct authentication code (MAC) for data
// using a matching MAC primitive in kh key handle and returns nil if so, otherwise it returns an error.
func (t *Crypto) VerifyMAC(macBytes, data []byte, kh interface{}) error {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return errBadKeyHandleFormat
	}

	macPrimitive, err := mac.New(keyHandle)
	if err != nil {
		return err
	}

	return macPrimitive.VerifyMAC(macBytes, data)
}

// WrapKey will do ECDH (ES or 1PU) key wrapping of cek using apu, apv and recipient public key 'recPubKey'.
// The optional 'wrapKeyOpts' specifies the sender kh for 1PU key wrapping.
// This function is used with the following parameters:
//  - Key Wrapping: ECDH-ES (no options)/ECDH-1PU (using crypto.WithSender() option) over A256KW as
// 		per https://tools.ietf.org/html/rfc7518#appendix-A.2
//  - KDF: Concat KDF as per https://tools.ietf.org/html/rfc7518#section-4.6
// returns the resulting key wrapping info as *composite.RecipientWrappedKey or error in case of wrapping failure.
func (t *Crypto) WrapKey(cek, apu, apv []byte, recPubKey *cryptoapi.PublicKey,
	wrapKeyOpts ...cryptoapi.WrapKeyOpts) (*cryptoapi.RecipientWrappedKey, error) {
	if recPubKey == nil {
		return nil, errors.New("wrapKey: recipient public key is required")
	}

	pOpts := cryptoapi.NewOpt()

	for _, opt := range wrapKeyOpts {
		opt(pOpts)
	}

	c, err := t.kw.getCurve(recPubKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to get curve of recipient key: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(recPubKey.X),
		Y:     new(big.Int).SetBytes(recPubKey.Y),
	}

	ephemeralPriv, err := t.kw.generateKey(pubKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to generate EPK: %w", err)
	}

	return t.deriveKEKAndWrap(cek, apu, apv, pOpts.SenderKey(), ephemeralPriv, pubKey, recPubKey.KID)
}

// UnwrapKey unwraps a key in recWK using ECDH (ES or 1PU) with recipient private key kh.
// The optional 'wrapKeyOpts' specifies the sender kh for 1PU key unwrapping.
// Note, if the option was used in WrapKey(), then it must be set here as well for a successful unwrapping.
// This function is used with the following parameters:
//  - Key Unwrapping: ECDH-ES (no options)/ECDH-1PU (using crypto.WithSender() option) over A256KW as
// 		per https://tools.ietf.org/html/rfc7518#appendix-A.2
//  - KDF: Concat KDF as per https://tools.ietf.org/html/rfc7518#section-4.6
// returns the resulting unwrapping key or error in case of unwrapping failure.
func (t *Crypto) UnwrapKey(recWK *cryptoapi.RecipientWrappedKey, kh interface{},
	wrapKeyOpts ...cryptoapi.WrapKeyOpts) ([]byte, error) {
	if recWK == nil {
		return nil, fmt.Errorf("unwrapKey: RecipientWrappedKey is empty")
	}

	pOpts := cryptoapi.NewOpt()

	for _, opt := range wrapKeyOpts {
		opt(pOpts)
	}

	privKey, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("unwrapKey: %w", errBadKeyHandleFormat)
	}

	recipientPrivateKey, err := extractPrivKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapKey: %w", err)
	}

	// TODO: add support for 25519 key wrapping https://github.com/hyperledger/aries-framework-go/issues/1637
	recPrivKey := hybridECPrivToECDSAKey(recipientPrivateKey)

	epkCurve, err := t.kw.getCurve(recWK.EPK.Curve)
	if err != nil {
		return nil, fmt.Errorf("unwrapKey: failed to GetCurve: %w", err)
	}

	if recipientPrivateKey.PublicKey.Curve != epkCurve {
		return nil, errors.New("unwrapKey: recipient and epk keys are not on the same curve")
	}

	epkPubKey := &ecdsa.PublicKey{
		Curve: epkCurve,
		X:     new(big.Int).SetBytes(recWK.EPK.X),
		Y:     new(big.Int).SetBytes(recWK.EPK.Y),
	}

	return t.deriveKEKAndUnwrap(recWK.Alg, recWK.EncryptedCEK, recWK.APU, recWK.APV, pOpts.SenderKey(),
		epkPubKey, recPrivKey)
}
