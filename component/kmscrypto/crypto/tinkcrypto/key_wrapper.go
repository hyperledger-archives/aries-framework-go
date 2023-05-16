/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	josecipher "github.com/go-jose/go-jose/v3/cipher"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

const defKeySize = 32

// deriveKEKAndWrap is the entry point for Crypto.WrapKey().
func (t *Crypto) deriveKEKAndWrap(cek, apu, apv, tag []byte, senderKH interface{}, recPubKey *cryptoapi.PublicKey,
	epkPrv *cryptoapi.PrivateKey, useXC20PKW bool) (*cryptoapi.RecipientWrappedKey, error) {
	var (
		kek         []byte
		epk         *cryptoapi.PublicKey
		wrappingAlg string
		err         error
	)

	if senderKH != nil { // ecdh1pu
		wrappingAlg, kek, epk, apu, err = t.derive1PUKEK(len(cek), apu, apv, tag, senderKH, recPubKey, epkPrv,
			useXC20PKW)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: error ECDH-1PU kek derivation: %w", err)
		}
	} else { // ecdhes
		wrappingAlg, kek, epk, apu, err = t.deriveESKEK(apu, apv, recPubKey, useXC20PKW)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: error ECDH-ES kek derivation: %w", err)
		}
	}

	return t.wrapRaw(kek, cek, apu, apv, wrappingAlg, recPubKey.KID, epk, useXC20PKW)
}

func (t *Crypto) wrapRaw(kek, cek, apu, apv []byte, alg, kid string, epk *cryptoapi.PublicKey,
	useXC20PKW bool) (*cryptoapi.RecipientWrappedKey, error) {
	var wk []byte

	if useXC20PKW { // nolint: nestif // XC20P key wrap
		aead, err := t.okpKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to create new XC20P primitive: %w", err)
		}

		wk, err = t.okpKW.wrap(aead, cek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to XC20P wrap key: %w", err)
		}
	} else { // A256GCM key wrap
		block, err := t.ecKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to create new AES Cipher: %w", err)
		}

		wk, err = t.ecKW.wrap(block, cek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to AES wrap key: %w", err)
		}
	}

	return &cryptoapi.RecipientWrappedKey{
		KID:          kid,
		EncryptedCEK: wk,
		EPK:          *epk,
		APU:          apu,
		APV:          apv,
		Alg:          alg,
	}, nil
}

// deriveKEKAndUnwrap is the entry point for Crypto.UnwrapKey().
func (t *Crypto) deriveKEKAndUnwrap(alg string, encCEK, apu, apv, tag []byte, epk *cryptoapi.PublicKey, senderKH,
	recKH interface{}) ([]byte, error) {
	var (
		kek []byte
		err error
	)

	recPrivKH, ok := recKH.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("deriveKEKAndUnwrap: %w", errBadKeyHandleFormat)
	}

	recipientPrivateKey, err := extractPrivKey(recPrivKH)
	if err != nil {
		return nil, fmt.Errorf("deriveKEKAndUnwrap: %w", err)
	}

	switch alg {
	case ECDH1PUA128KWAlg, ECDH1PUA192KWAlg, ECDH1PUA256KWAlg, ECDH1PUXC20PKWAlg:
		kek, err = t.derive1PUKEKForUnwrap(alg, apu, apv, tag, epk, senderKH, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: error ECDH-1PU kek derivation: %w", err)
		}
	case ECDHESA256KWAlg, ECDHESXC20PKWAlg:
		kek, err = t.deriveESKEKForUnwrap(alg, apu, apv, epk, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: error ECDH-ES kek derivation: %w", err)
		}
	default:
		return nil, fmt.Errorf("deriveKEKAndUnwrap: unsupported JWE KW Alg '%s'", alg)
	}

	return t.unwrapRaw(alg, kek, encCEK)
}

func (t *Crypto) unwrapRaw(alg string, kek, encCEK []byte) ([]byte, error) {
	var wk []byte

	// key unwrapping does not depend on an option (like key wrapping), because kw primitive can be detected from alg.
	switch alg {
	case ECDHESXC20PKWAlg, ECDH1PUXC20PKWAlg: // XC20P key unwrap
		aead, err := t.okpKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to create new XC20P primitive: %w", err)
		}

		wk, err = t.okpKW.unwrap(aead, encCEK)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to XC20P unwrap key: %w", err)
		}
	case ECDHESA256KWAlg, ECDH1PUA128KWAlg, ECDH1PUA192KWAlg, ECDH1PUA256KWAlg:
		// A256GCM key (ES) unwrap or CBC+HMAC (1PU)
		block, err := t.ecKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to create new AES Cipher: %w", err)
		}

		wk, err = t.ecKW.unwrap(block, encCEK)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to AES unwrap key: %w", err)
		}
	default:
		return nil, fmt.Errorf("deriveKEKAndUnwrap: cannot unwrap with bad kw alg: '%s'", alg)
	}

	return wk, nil
}

func (t *Crypto) derive1PUKEK(cekSize int, apu, apv, tag []byte, senderKH interface{}, recPubKey *cryptoapi.PublicKey,
	epkPrv *cryptoapi.PrivateKey, useXC20PKW bool) (string, []byte, *cryptoapi.PublicKey, []byte, error) {
	var (
		kek         []byte
		epk         *cryptoapi.PublicKey
		err         error
		wrappingAlg string
	)

	two := 2

	if useXC20PKW {
		wrappingAlg = ECDH1PUXC20PKWAlg
	} else {
		switch cekSize {
		case subtle.AES128Size * two:
			wrappingAlg = ECDH1PUA128KWAlg
		case subtle.AES192Size * two:
			wrappingAlg = ECDH1PUA192KWAlg
		case subtle.AES256Size * two:
			wrappingAlg = ECDH1PUA256KWAlg
		default:
			return "", nil, nil, nil, fmt.Errorf("derive1PUKEK: invalid CBC-HMAC key size %d", cekSize)
		}
	}

	switch recPubKey.Type {
	case ecdhpb.KeyType_EC.String():
		wrappingAlg, kek, epk, apu, err = t.derive1PUWithECKey(wrappingAlg, apu, apv, tag, senderKH, recPubKey, epkPrv)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("derive1PUKEK: EC key derivation error %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		wrappingAlg, kek, epk, apu, err = t.derive1PUWithOKPKey(wrappingAlg, apu, apv, tag, senderKH, recPubKey, epkPrv)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("derive1PUKEK: OKP key derivation error %w", err)
		}
	default:
		return "", nil, nil, nil, errors.New("derive1PUKEK: invalid recipient key type for ECDH-1PU")
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (t *Crypto) derive1PUKEKForUnwrap(alg string, apu, apv, tag []byte, epk *cryptoapi.PublicKey, senderKH interface{},
	recipientPrivateKey interface{}) ([]byte, error) {
	var (
		kek []byte
		err error
	)

	if senderKH == nil {
		return nil, fmt.Errorf("derive1PUKEKForUnwrap: sender's public keyset handle option is required for '%s'",
			ECDH1PUA256KWAlg)
	}

	switch epk.Type {
	case ecdhpb.KeyType_EC.String():
		kek, err = t.derive1PUWithECKeyForUnwrap(alg, apu, apv, tag, epk, senderKH, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("derive1PUKEKForUnwrap: EC key derivation error %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		kek, err = t.derive1PUWithOKPKeyForUnwrap(alg, apu, apv, tag, epk, senderKH, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("derive1PUKEKForUnwrap: OKP key derivation error %w", err)
		}
	default:
		return nil, errors.New("derive1PUKEKForUnwrap: invalid EPK key type for ECDH-1PU")
	}

	return kek, nil
}

func (t *Crypto) deriveESKEK(apu, apv []byte, recPubKey *cryptoapi.PublicKey,
	useXC20PKW bool) (string, []byte, *cryptoapi.PublicKey, []byte, error) {
	var (
		kek         []byte
		epk         *cryptoapi.PublicKey
		wrappingAlg string
		err         error
	)

	switch recPubKey.Type {
	case ecdhpb.KeyType_EC.String():
		wrappingAlg, kek, epk, apu, err = t.deriveESWithECKey(apu, apv, recPubKey, useXC20PKW)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("deriveESKEK: error %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		wrappingAlg, kek, epk, apu, err = t.deriveESWithOKPKey(apu, apv, recPubKey, useXC20PKW)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("deriveESKEK: error %w", err)
		}
	default:
		return "", nil, nil, nil, errors.New("deriveESKEK: invalid recipient key type for ECDH-ES")
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (t *Crypto) deriveESKEKForUnwrap(alg string, apu, apv []byte, epk *cryptoapi.PublicKey,
	recipientPrivateKey interface{}) ([]byte, error) {
	var (
		kek []byte
		err error
	)

	switch epk.Type {
	case ecdhpb.KeyType_EC.String():
		kek, err = t.deriveESWithECKeyForUnwrap(alg, apu, apv, epk, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("deriveESKEKForUnwrap: error: %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		kek, err = t.deriveESWithOKPKeyForUnwrap(alg, apu, apv, epk, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("deriveESKEKForUnwrap: error: %w", err)
		}
	default:
		return nil, errors.New("deriveESKEKForUnwrap: invalid EPK key type for ECDH-ES")
	}

	return kek, nil
}

func (t *Crypto) derive1PUWithECKey(wrappingAlg string, apu, apv, tag []byte, senderKH interface{},
	recPubKey *cryptoapi.PublicKey, epkPrv *cryptoapi.PrivateKey) (string, []byte, *cryptoapi.PublicKey, []byte, error) {
	senderPrivKey, err := ksToPrivateECDSAKey(senderKH)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithECKey: failed to retrieve sender key: %w", err)
	}

	pubKey, ephemeralPrivKey, err := t.convertRecKeyAndGenOrGetEPKEC(recPubKey, epkPrv)
	if err != nil {
		return "", nil, nil, nil, err
	}

	ephemeralXBytes := ephemeralPrivKey.PublicKey.X.Bytes()

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralXBytes)))
		base64.RawURLEncoding.Encode(apu, ephemeralXBytes)
	}

	keySize := aesCEKSize1PU(wrappingAlg)

	kek, err := t.ecKW.deriveSender1Pu(wrappingAlg, apu, apv, tag, ephemeralPrivKey, senderPrivKey, pubKey, keySize)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithECKey: failed to derive key: %w", err)
	}

	epk := &cryptoapi.PublicKey{
		X:     ephemeralXBytes,
		Y:     ephemeralPrivKey.PublicKey.Y.Bytes(),
		Curve: ephemeralPrivKey.PublicKey.Curve.Params().Name,
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (t *Crypto) derive1PUWithECKeyForUnwrap(alg string, apu, apv, tag []byte, epk *cryptoapi.PublicKey,
	senderKH interface{}, recipientPrivateKey interface{}) ([]byte, error) {
	var (
		senderPubKey *ecdsa.PublicKey
		epkCurve     elliptic.Curve
		err          error
	)

	senderPubKey, err = ksToPublicECDSAKey(senderKH, t.ecKW)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithECKeyForUnwrap: failed to retrieve sender key: %w", err)
	}

	epkCurve, err = t.ecKW.getCurve(epk.Curve)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithECKeyForUnwrap: failed to GetCurve: %w", err)
	}

	epkPubKey := &ecdsa.PublicKey{
		Curve: epkCurve,
		X:     new(big.Int).SetBytes(epk.X),
		Y:     new(big.Int).SetBytes(epk.Y),
	}

	recPrivECKey, ok := recipientPrivateKey.(*hybrid.ECPrivateKey)
	if !ok {
		return nil, errors.New("derive1PUWithECKeyForUnwrap: recipient key is not an EC key")
	}

	recPrivKey := hybridECPrivToECDSAKey(recPrivECKey)

	keySize := aesCEKSize1PU(alg)

	kek, err := t.ecKW.deriveRecipient1Pu(alg, apu, apv, tag, epkPubKey, senderPubKey, recPrivKey, keySize)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithECKeyForUnwrap: failed to derive kek: %w", err)
	}

	return kek, nil
}

func aesCEKSize1PU(alg string) int {
	keySize := defKeySize
	two := 2

	switch alg {
	case ECDH1PUA128KWAlg:
		keySize = subtle.AES128Size * two
	case ECDH1PUA192KWAlg:
		keySize = subtle.AES192Size * two
	case ECDH1PUA256KWAlg:
		keySize = subtle.AES256Size * two
	}

	return keySize
}

func (t *Crypto) deriveESWithECKeyForUnwrap(alg string, apu, apv []byte, epk *cryptoapi.PublicKey,
	recipientPrivateKey interface{}) ([]byte, error) {
	var (
		epkCurve elliptic.Curve
		err      error
	)

	epkCurve, err = t.ecKW.getCurve(epk.Curve)
	if err != nil {
		return nil, fmt.Errorf("deriveESWithECKeyForUnwrap: failed to GetCurve: %w", err)
	}

	epkPubKey := &ecdsa.PublicKey{
		Curve: epkCurve,
		X:     new(big.Int).SetBytes(epk.X),
		Y:     new(big.Int).SetBytes(epk.Y),
	}

	recPrivECKey, ok := recipientPrivateKey.(*hybrid.ECPrivateKey)
	if !ok {
		return nil, errors.New("deriveESWithECKeyForUnwrap: recipient key is not an EC key")
	}

	recPrivKey := hybridECPrivToECDSAKey(recPrivECKey)

	if recPrivKey.Curve != epkPubKey.Curve {
		return nil, errors.New("deriveESWithECKeyForUnwrap: recipient and ephemeral keys are not on the same curve")
	}

	return josecipher.DeriveECDHES(alg, apu, apv, recPrivKey, epkPubKey, defKeySize), nil
}

func (t *Crypto) deriveESWithECKey(apu, apv []byte, recPubKey *cryptoapi.PublicKey,
	useXC20PKW bool) (string, []byte, *cryptoapi.PublicKey, []byte, error) {
	wrappingAlg := ECDHESA256KWAlg

	if useXC20PKW {
		wrappingAlg = ECDHESXC20PKWAlg
	}

	recECPubKey, ephemeralPrivKey, err := t.convertRecKeyAndGenOrGetEPKEC(recPubKey, nil)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("deriveESWithECKey: failed to generate ephemeral key: %w", err)
	}

	ephemeralXBytes := ephemeralPrivKey.PublicKey.X.Bytes()

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralXBytes)))
		base64.RawURLEncoding.Encode(apu, ephemeralXBytes)
	}

	kek := josecipher.DeriveECDHES(wrappingAlg, apu, apv, ephemeralPrivKey, recECPubKey, defKeySize)
	epk := &cryptoapi.PublicKey{
		X:     ephemeralXBytes,
		Y:     ephemeralPrivKey.PublicKey.Y.Bytes(),
		Curve: ephemeralPrivKey.PublicKey.Curve.Params().Name,
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (t *Crypto) derive1PUWithOKPKey(wrappingAlg string, apu, apv, tag []byte, senderKH interface{},
	recPubKey *cryptoapi.PublicKey, epkPrv *cryptoapi.PrivateKey) (string, []byte, *cryptoapi.PublicKey, []byte, error) {
	senderPrivKey, err := ksToPrivateX25519Key(senderKH)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithOKPKey: failed to retrieve sender key: %w", err)
	}

	ephemeralPubKey, ephemeralPrivKey, err := t.generateOrGetEphemeralOKPKey(epkPrv)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithOKPKey: failed to generate ephemeral key: %w", err)
	}

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralPubKey)))
		base64.RawURLEncoding.Encode(apu, ephemeralPubKey)
	}

	kek, err := t.okpKW.deriveSender1Pu(wrappingAlg, apu, apv, tag, ephemeralPrivKey, senderPrivKey, recPubKey.X,
		defKeySize)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithOKPKey: failed to derive key: %w", err)
	}

	epk := &cryptoapi.PublicKey{
		X:     ephemeralPubKey,
		Curve: "X25519",
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (t *Crypto) derive1PUWithOKPKeyForUnwrap(alg string, apu, apv, tag []byte, epk *cryptoapi.PublicKey,
	senderKH interface{}, recipientPrivateKey interface{}) ([]byte, error) {
	senderPubKey, err := ksToPublicX25519Key(senderKH)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithOKPKeyForUnwrap: failed to retrieve sender key: %w", err)
	}

	recPrivOKPKey, ok := recipientPrivateKey.([]byte)
	if !ok {
		return nil, errors.New("derive1PUWithOKPKeyForUnwrap: recipient key is not an OKP key")
	}

	kek, err := t.okpKW.deriveRecipient1Pu(alg, apu, apv, tag, epk.X, senderPubKey, recPrivOKPKey, defKeySize)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithOKPKeyForUnwrap: failed to derive kek: %w", err)
	}

	return kek, nil
}

func (t *Crypto) deriveESWithOKPKey(apu, apv []byte, recPubKey *cryptoapi.PublicKey,
	useXC20PKW bool) (string, []byte, *cryptoapi.PublicKey, []byte, error) {
	wrappingAlg := ECDHESA256KWAlg

	if useXC20PKW {
		wrappingAlg = ECDHESXC20PKWAlg
	}

	ephemeralPubKey, ephemeralPrivKey, err := t.generateOrGetEphemeralOKPKey(nil)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("deriveESWithOKPKey: failed to generate ephemeral key: %w", err)
	}

	ephemeralPrivChacha := new([chacha20poly1305.KeySize]byte)
	copy(ephemeralPrivChacha[:], ephemeralPrivKey)

	recPubKeyChacha := new([chacha20poly1305.KeySize]byte)
	copy(recPubKeyChacha[:], recPubKey.X)

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralPubKey)))
		base64.RawURLEncoding.Encode(apu, ephemeralPubKey)
	}

	z, err := cryptoutil.DeriveECDHX25519(ephemeralPrivChacha, recPubKeyChacha)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("deriveESWithOKPKey: failed to derive 25519 kek: %w", err)
	}

	kek := kdf(wrappingAlg, z, apu, apv, chacha20poly1305.KeySize)

	epk := &cryptoapi.PublicKey{
		X:     ephemeralPubKey,
		Curve: "X25519",
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (t *Crypto) deriveESWithOKPKeyForUnwrap(alg string, apu, apv []byte, epk *cryptoapi.PublicKey,
	recipientPrivateKey interface{}) ([]byte, error) {
	recPrivOKPKey, ok := recipientPrivateKey.([]byte)
	if !ok {
		return nil, errors.New("deriveESWithOKPKeyForUnwrap: recipient key is not an OKP key")
	}

	recPrivKeyChacha := new([chacha20poly1305.KeySize]byte)
	copy(recPrivKeyChacha[:], recPrivOKPKey)

	epkChacha := new([chacha20poly1305.KeySize]byte)
	copy(epkChacha[:], epk.X)

	z, err := cryptoutil.DeriveECDHX25519(recPrivKeyChacha, epkChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveESWithOKPKeyForUnwrap: %w", err)
	}

	return kdf(alg, z, apu, apv, chacha20poly1305.KeySize), nil
}

// convertRecKeyAndGenOrGetEPKEC converts recPubKey into *ecdsa.PublicKey and generates an ephemeral EC private key
// as *ecdsa.PrivateKey.
func (t *Crypto) convertRecKeyAndGenOrGetEPKEC(recPubKey *cryptoapi.PublicKey,
	prvEPK *cryptoapi.PrivateKey) (*ecdsa.PublicKey, *ecdsa.PrivateKey,
	error) {
	c, err := t.ecKW.getCurve(recPubKey.Curve)
	if err != nil {
		return nil, nil, fmt.Errorf("convertRecKeyAndGenOrGetEPKEC: failed to get curve of recipient key: %w",
			err)
	}

	recECPubKey := &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(recPubKey.X),
		Y:     new(big.Int).SetBytes(recPubKey.Y),
	}

	if prvEPK == nil {
		ephemeralPrivKey, err := t.ecKW.generateKey(recECPubKey.Curve)
		if err != nil {
			return nil, nil, fmt.Errorf("convertRecKeyAndGenOrGetEPKEC: failed to generate EPK: %w", err)
		}

		return recECPubKey, ephemeralPrivKey.(*ecdsa.PrivateKey), nil
	}

	return recECPubKey, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: c,
			X:     new(big.Int).SetBytes(prvEPK.PublicKey.X),
			Y:     new(big.Int).SetBytes(prvEPK.PublicKey.Y),
		},
		D: new(big.Int).SetBytes(prvEPK.D),
	}, nil
}

func (t *Crypto) generateOrGetEphemeralOKPKey(epkPrv *cryptoapi.PrivateKey) ([]byte, []byte, error) {
	if epkPrv == nil {
		ephemeralPrivKey, err := t.okpKW.generateKey(nil)
		if err != nil {
			return nil, nil, err
		}

		ephemeralPrivKeyByte, ok := ephemeralPrivKey.([]byte)
		if !ok {
			return nil, nil, errors.New("invalid ephemeral key type, not OKP, want []byte for OKP")
		}

		ephemeralPubKey, err := curve25519.X25519(ephemeralPrivKeyByte, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}

		return ephemeralPubKey, ephemeralPrivKeyByte, nil
	}

	return epkPrv.PublicKey.X, epkPrv.D, nil
}

func ksToPrivateECDSAKey(ks interface{}) (*ecdsa.PrivateKey, error) {
	senderKH, ok := ks.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("ksToPrivateECDSAKey: %w", errBadKeyHandleFormat)
	}

	senderHPrivKey, err := extractPrivKey(senderKH)
	if err != nil {
		return nil, fmt.Errorf("ksToPrivateECDSAKey: failed to extract sender key: %w", err)
	}

	prvKey, ok := senderHPrivKey.(*hybrid.ECPrivateKey)
	if !ok {
		return nil, errors.New("ksToPrivateECDSAKey: not an EC key")
	}

	return hybridECPrivToECDSAKey(prvKey), nil
}

func ksToPrivateX25519Key(ks interface{}) ([]byte, error) {
	senderKH, ok := ks.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("ksToPrivateX25519Key: %w", errBadKeyHandleFormat)
	}

	senderPrivKey, err := extractPrivKey(senderKH)
	if err != nil {
		return nil, fmt.Errorf("ksToPrivateX25519Key: failed to extract sender key: %w", err)
	}

	prvKey, ok := senderPrivKey.([]byte)
	if !ok {
		return nil, errors.New("ksToPrivateX25519Key: not an OKP key")
	}

	return prvKey, nil
}

func ksToPublicECDSAKey(ks interface{}, kw keyWrapper) (*ecdsa.PublicKey, error) {
	switch kst := ks.(type) {
	case *keyset.Handle:
		sPubKey, err := keyio.ExtractPrimaryPublicKey(kst)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicECDSAKey: failed to extract public key from keyset handle: %w", err)
		}

		sCurve, err := kw.getCurve(sPubKey.Curve)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicECDSAKey: failed to GetCurve: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: sCurve,
			X:     new(big.Int).SetBytes(sPubKey.X),
			Y:     new(big.Int).SetBytes(sPubKey.Y),
		}, nil
	case *cryptoapi.PublicKey:
		sCurve, err := kw.getCurve(kst.Curve)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicECDSAKey: failed to GetCurve: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: sCurve,
			X:     new(big.Int).SetBytes(kst.X),
			Y:     new(big.Int).SetBytes(kst.Y),
		}, nil
	case *ecdsa.PublicKey:
		return kst, nil
	default:
		return nil, fmt.Errorf("ksToPublicECDSAKey: unsupported keyset type %+v", kst)
	}
}

func ksToPublicX25519Key(ks interface{}) ([]byte, error) {
	switch kst := ks.(type) {
	case *keyset.Handle:
		sPubKey, err := keyio.ExtractPrimaryPublicKey(kst)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicX25519Key: failed to extract public key from keyset handle: %w", err)
		}

		return sPubKey.X, nil
	case *cryptoapi.PublicKey:
		return kst.X, nil
	default:
		return nil, fmt.Errorf("ksToPublicX25519Key: unsupported keyset type %+v", kst)
	}
}
