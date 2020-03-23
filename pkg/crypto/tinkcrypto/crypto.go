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
	"errors"
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	aeadsubtle "github.com/google/tink/go/subtle/aead"
	"golang.org/x/crypto/chacha20poly1305"
)

var errBadKeyHandleFormat = errors.New("bad key handle format")

// Package provider/tinkcrypto includes implementation of spi/crypto. SPI implementation will be built
// as a Framework option and fed into pkg/common/crypto implementation that includes a combined crypto
// and kms API to be used everywhere by the framework.

// Crypto is the default Crypto SPI implementation using Tink
type Crypto struct {
}

// New creates a new Crypto instance
func New() (*Crypto, error) {
	return &Crypto{}, nil
}

// Encrypt will encrypt msg using the implementation's corresponding encryption key and primitive in kh
func (t *Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, nil, errBadKeyHandleFormat
	}

	a, err := aead.New(keyHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("create new aead: %w", err)
	}

	ct, err := a.Encrypt(msg, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt msg: %w", err)
	}

	ps, err := keyHandle.Primitives()
	if err != nil {
		return nil, nil, fmt.Errorf("get primitives: %w", err)
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

// Decrypt will decrypt cipher using the implementation's corresponding encryption key referenced by kh
func (t *Crypto) Decrypt(cipher, nonce, aad []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	a, err := aead.New(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new aead: %w", err)
	}

	ps, err := keyHandle.Primitives()
	if err != nil {
		return nil, fmt.Errorf("get primitives: %w", err)
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

// Sign will sign msg using the implementation's corresponding signing key referenced by kh
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

// Verify will verify sig signature of msg using the implementation's corresponding signing key referenced by kh
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
// using a matching MAC primitive in kh key handle
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
