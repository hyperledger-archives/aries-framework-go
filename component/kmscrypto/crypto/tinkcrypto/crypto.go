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
	aeadsubtle "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs"
)

const (
	// ECDHESA256KWAlg is the ECDH-ES with AES-GCM 256 key wrapping algorithm.
	ECDHESA256KWAlg = "ECDH-ES+A256KW"
	// ECDH1PUA128KWAlg is the ECDH-1PU with AES-CBC 128+HMAC-SHA 256 key wrapping algorithm.
	ECDH1PUA128KWAlg = "ECDH-1PU+A128KW"
	// ECDH1PUA192KWAlg is the ECDH-1PU with AES-CBC 192+HMAC-SHA 384 key wrapping algorithm.
	ECDH1PUA192KWAlg = "ECDH-1PU+A192KW"
	// ECDH1PUA256KWAlg is the ECDH-1PU with AES-CBC 256+HMAC-SHA 512 key wrapping algorithm.
	ECDH1PUA256KWAlg = "ECDH-1PU+A256KW"
	// ECDHESXC20PKWAlg is the ECDH-ES with XChacha20Poly1305 key wrapping algorithm.
	ECDHESXC20PKWAlg = "ECDH-ES+XC20PKW"
	// ECDH1PUXC20PKWAlg is the ECDH-1PU with XChacha20Poly1305 key wrapping algorithm.
	ECDH1PUXC20PKWAlg = "ECDH-1PU+XC20PKW"

	nistPECDHKWPrivateKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
	x25519ECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey"
)

var errBadKeyHandleFormat = errors.New("bad key handle format")

// Package tinkcrypto includes the default implementation of pkg/crypto. It uses Tink for executing crypto primitives
// and will be built as a framework option. It represents the main crypto service in the framework. `kh interface{}`
// arguments in this implementation represent Tink's `*keyset.Handle`, using this type provides easy integration with
// Tink and the default KMS service.

// Crypto is the default Crypto SPI implementation using Tink.
type Crypto struct {
	ecKW  keyWrapper
	okpKW keyWrapper
}

// New creates a new Crypto instance.
func New() (*Crypto, error) {
	return &Crypto{ecKW: &ecKWSupport{}, okpKW: &okpKWSupport{}}, nil
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
	case *aeadsubtle.EncryptThenAuthenticate:
		// AESCBC+HMACSHA Tink keys use Tink's EncryptThenAuthenticate AEAD primitive as per the CBC hmac key manager's
		// Primitive() call.
		ivSize = subtle.AES128Size
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

	for prefix := range ps.Entries {
		// since Tink expects the key prefix + nonce as the ciphertext prefix, prepend them prior to calling its Decrypt()
		ct := make([]byte, 0, len(prefix)+len(nonce)+len(cipher))
		ct = append(ct, prefix...)
		ct = append(ct, nonce...)
		ct = append(ct, cipher...)

		pt, e := a.Decrypt(ct, aad)

		if e == nil {
			return pt, nil
		}
	}

	return nil, fmt.Errorf("decrypt cipher: decryption failed")
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
// This function is used with the following parameters:
//   - Key Wrapping: `ECDH-ES` (no options) or `ECDH-1PU` (using crypto.WithSender() option in wrapKeyOpts) over either:
//   - `ECDH-ES+A256KW` alg (AES256-GCM, default anoncrypt KW with no options) as per
//     https://tools.ietf.org/html/rfc7518#appendix-A.2
//   - `ECDH-ES+XC20PKW` alg (XChacha20Poly1305, anoncrypt using crypto.WithXC20PKW() option in wrapKeyOpts).
//     The following ECDH-1PU algs are triggered using the crypto.WithSender() and crypto.WithTag() options in
//     wrapKeyOpts:
//   - `ECDH-1PU+A128KW` alg (AES128-GCM, authcrypt KW using cek size=32).
//   - `ECDH-1PU+A192KW` alg (AES192-GCM, authcrypt KW using cek size=48).
//   - `ECDH-1PU+A256KW` alg (AES256-GCM, authcrypt KW using cek size=64).
//   - `ECDH-1PU+XC20PKW` alg (XChacha20Poly1305, authcrypt using crypto.WithXC20PKW() with cek size=32).
//   - KDF (based on recPubKey.Curve):
//     `Concat KDF` as per https://tools.ietf.org/html/rfc7518#section-4.6 (for recPubKey with NIST P curves) or
//     `Curve25519`+`Concat KDF` as per https://tools.ietf.org/html/rfc7748#section-6.1
//     (for recPubKey with X25519 curve).
//
// returns the resulting key wrapping info as *composite.RecipientWrappedKey or error in case of wrapping failure.
func (t *Crypto) WrapKey(cek, apu, apv []byte, recPubKey *crypto.PublicKey,
	wrapKeyOpts ...crypto.WrapKeyOpts) (*crypto.RecipientWrappedKey, error) {
	if recPubKey == nil {
		return nil, errors.New("wrapKey: recipient public key is required")
	}

	pOpts := crypto.NewOpt()

	for _, opt := range wrapKeyOpts {
		opt(pOpts)
	}

	wk, err := t.deriveKEKAndWrap(cek, apu, apv, pOpts.Tag(), pOpts.SenderKey(), recPubKey, pOpts.EPK(),
		pOpts.UseXC20PKW())
	if err != nil {
		return nil, fmt.Errorf("wrapKey: %w", err)
	}

	return wk, nil
}

// UnwrapKey unwraps a key in recWK using ECDH (ES or 1PU) with recipient private key kh.
// This function is used with the following parameters:
//   - Key Unwrapping: `ECDH-ES` (no options) or `ECDH-1PU` (using crypto.WithSender() option in wrapKeyOpts)
//     over either
//   - `ECDH-ES+A256KW` alg (AES256-GCM, default anoncrypt KW with no options) as per
//     https://tools.ietf.org/html/rfc7518#appendix-A.2
//   - `ECDH-ES+XC20PKW` alg (XChacha20Poly1305, anoncrypt using crypto.WithXC20PKW() option in wrapKeyOpts).
//     The following ECDH-1PU algs are triggered using the crypto.WithSender() and crypto.WithTag() options in
//     wrapKeyOpts:
//   - `ECDH-1PU+A128KW` alg (AES128-GCM, authcrypt KW using cek size=32).
//   - `ECDH-1PU+A192KW` alg (AES192-GCM, authcrypt KW using cek size=48).
//   - `ECDH-1PU+A256KW` alg (AES256-GCM, authcrypt KW using cek size=64).
//   - `ECDH-1PU+XC20PKW` alg (XChacha20Poly1305, authcrypt using crypto.WithXC20PKW() with cek size=32).
//   - KDF (based on recWk.EPK.KeyType): `Concat KDF` as per https://tools.ietf.org/html/rfc7518#section-4.6 (for type
//     value as EC) or `Curve25519`+`Concat KDF` as per https://tools.ietf.org/html/rfc7748#section-6.1 (for type value
//     as OKP, ie X25519 key).
//
// returns the resulting unwrapping key or error in case of unwrapping failure.
//
// Notes:
// 1- if the crypto.WithSender() option was used in WrapKey(), then it must be set here as well for successful key
//
//	unwrapping.
//
// 2- unwrapping a key with recWK.alg value set as either `ECDH-1PU+A128KW`, `ECDH-1PU+A192KW`, `ECDH-1PU+A256KW` or
//
//	`ECDH-1PU+XC20PKW` requires the use of crypto.WithSender() option (containing the sender public key) in order to
//	execute ECDH-1PU derivation.
//
// 3- the ephemeral key in recWK.EPK must have the same KeyType as the recipientKH and the same Curve for NIST P
//
//	curved keys. Unwrapping a key with non matching types/curves will result in unwrapping failure.
//
// 4- recipientKH must contain the private key since unwrapping is usually done on the recipient side.
func (t *Crypto) UnwrapKey(recWK *crypto.RecipientWrappedKey, recipientKH interface{},
	wrapKeyOpts ...crypto.WrapKeyOpts) ([]byte, error) {
	if recWK == nil {
		return nil, fmt.Errorf("unwrapKey: RecipientWrappedKey is empty")
	}

	pOpts := crypto.NewOpt()

	for _, opt := range wrapKeyOpts {
		opt(pOpts)
	}

	key, err := t.deriveKEKAndUnwrap(recWK.Alg, recWK.EncryptedCEK, recWK.APU, recWK.APV, pOpts.Tag(), &recWK.EPK,
		pOpts.SenderKey(), recipientKH)
	if err != nil {
		return nil, fmt.Errorf("unwrapKey: %w", err)
	}

	return key, nil
}

// SignMulti will create a BBS+ signature of messages using the signer's private key in signerKH handle.
// returns:
//
//	signature in []byte
//	error in case of errors
func (t *Crypto) SignMulti(messages [][]byte, signerKH interface{}) ([]byte, error) {
	keyHandle, ok := signerKH.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	signer, err := bbs.NewSigner(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new BBS+ signer: %w", err)
	}

	s, err := signer.Sign(messages)
	if err != nil {
		return nil, fmt.Errorf("BBS+ sign msg: %w", err)
	}

	return s, nil
}

// VerifyMulti will BBS+ verify a signature of messages against the signer's public key in signerPubKH handle.
// returns:
//
//	error in case of errors or nil if signature verification was successful
func (t *Crypto) VerifyMulti(messages [][]byte, bbsSignature []byte, signerPubKH interface{}) error {
	keyHandle, ok := signerPubKH.(*keyset.Handle)
	if !ok {
		return errBadKeyHandleFormat
	}

	verifier, err := bbs.NewVerifier(keyHandle)
	if err != nil {
		return fmt.Errorf("create new BBS+ verifier: %w", err)
	}

	err = verifier.Verify(messages, bbsSignature)
	if err != nil {
		err = fmt.Errorf("BBS+ verify msg: %w", err)
	}

	return err
}

// VerifyProof will verify a BBS+ signature proof (generated e.g. by Verifier's DeriveProof() call) for revealedMessages
// with the signer's public key in signerPubKH handle.
// returns:
//
//	error in case of errors or nil if signature proof verification was successful
func (t *Crypto) VerifyProof(revealedMessages [][]byte, proof, nonce []byte, signerPubKH interface{}) error {
	keyHandle, ok := signerPubKH.(*keyset.Handle)
	if !ok {
		return errBadKeyHandleFormat
	}

	verifier, err := bbs.NewVerifier(keyHandle)
	if err != nil {
		return fmt.Errorf("create new BBS+ verifier: %w", err)
	}

	err = verifier.VerifyProof(revealedMessages, proof, nonce)
	if err != nil {
		err = fmt.Errorf("verify proof msg: %w", err)
	}

	return err
}

// DeriveProof will create a BBS+ signature proof for a list of revealed messages using BBS signature
// (can be built using a Signer's SignMulti() call) and the signer's public key in signerPubKH handle.
// returns:
//
//	signature proof in []byte
//	error in case of errors
func (t *Crypto) DeriveProof(messages [][]byte, bbsSignature, nonce []byte, revealedIndexes []int,
	signerPubKH interface{}) ([]byte, error) {
	keyHandle, ok := signerPubKH.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	verifier, err := bbs.NewVerifier(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new BBS+ verifier: %w", err)
	}

	proof, err := verifier.DeriveProof(messages, bbsSignature, nonce, revealedIndexes)
	if err != nil {
		return nil, fmt.Errorf("verify proof msg: %w", err)
	}

	return proof, nil
}
