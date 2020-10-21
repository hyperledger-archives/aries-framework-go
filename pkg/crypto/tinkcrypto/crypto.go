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
	josecipher "github.com/square/go-jose/v3/cipher"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	ecdhessubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
)

const (
	ecdhesKWAlg = ecdhessubtle.A256KWAlg
	keySize     = 32
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

// Encrypt will encrypt msg using the implementation's corresponding encryption key and primitive in kh.
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

// Decrypt will decrypt cipher using the implementation's corresponding encryption key referenced by kh.
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

// Sign will sign msg using the implementation's corresponding signing key referenced by kh.
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

// Verify will verify sig signature of msg using the implementation's corresponding signing key referenced by kh.
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

// WrapKey will do ECDHES key wrapping of cek using apu, apv and recipient public key found in kh.
func (t *Crypto) WrapKey(cek, apu, apv []byte, kh interface{}) (*composite.RecipientWrappedKey, error) {
	// TODO: add support for 25519 key wrapping https://github.com/hyperledger/aries-framework-go/issues/1637
	keyType := compositepb.KeyType_EC.String()

	pubKH, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("wrapKey: %w", errBadKeyHandleFormat)
	}

	pubKey, err := keyio.ExtractPrimaryPublicKey(pubKH)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to extract recipient public key from kh: %w", err)
	}

	c, err := t.kw.getCurve(pubKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to get curve of recipient key: %w", err)
	}

	recPubKey := &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(pubKey.X),
		Y:     new(big.Int).SetBytes(pubKey.Y),
	}

	ephemeralPriv, err := t.kw.generateKey(recPubKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to generate EPK: %w", err)
	}

	kek := josecipher.DeriveECDHES(ecdhesKWAlg, apu, apv, ephemeralPriv, recPubKey, keySize)

	block, err := t.kw.createCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to create new Cipher: %w", err)
	}

	wk, err := t.kw.wrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to wrap key: %w", err)
	}

	return &composite.RecipientWrappedKey{
		KID:          pubKey.KID,
		EncryptedCEK: wk,
		EPK: composite.PublicKey{
			X:     ephemeralPriv.PublicKey.X.Bytes(),
			Y:     ephemeralPriv.PublicKey.Y.Bytes(),
			Curve: ephemeralPriv.PublicKey.Curve.Params().Name,
			Type:  keyType,
		},
		APU: apu,
		APV: apv,
		Alg: ecdhesKWAlg,
	}, nil
}

// UnwrapKey unwraps a key in recWK using ECDHES with recipient private key kh.
func (t *Crypto) UnwrapKey(recWK *composite.RecipientWrappedKey, kh interface{}) ([]byte, error) {
	if recWK == nil {
		return nil, fmt.Errorf("unwrapKey: RecipientWrappedKey is empty")
	}

	// only ECDHES KW alg is supported (for now)
	if recWK.Alg != ecdhesKWAlg {
		return nil, fmt.Errorf("unwrapKey: unsupported JWE KW Alg '%s'", recWK.Alg)
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
	recPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: recipientPrivateKey.PublicKey.Curve,
			X:     recipientPrivateKey.PublicKey.Point.X,
			Y:     recipientPrivateKey.PublicKey.Point.Y,
		},
		D: recipientPrivateKey.D,
	}

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

	// DeriveECDHES checks if keys are on the same curve
	kek := josecipher.DeriveECDHES(recWK.Alg, recWK.APU, recWK.APV, recPrivKey, epkPubKey, keySize)

	block, err := t.kw.createCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("unwrapKey: failed to create new Cipher: %w", err)
	}

	wk, err := t.kw.unwrap(block, recWK.EncryptedCEK)
	if err != nil {
		return nil, fmt.Errorf("unwrapKey: failed to unwrap key: %w", err)
	}

	return wk, nil
}
