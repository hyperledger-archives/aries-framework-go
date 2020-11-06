/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	josecipher "github.com/square/go-jose/v3/cipher"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

const defKeySize = 32

type keyWrapper interface {
	getCurve(curve string) (elliptic.Curve, error)
	generateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error)
	createCipher(key []byte) (cipher.Block, error)
	wrap(block cipher.Block, cek []byte) ([]byte, error)
	unwrap(block cipher.Block, encryptedKey []byte) ([]byte, error)
	deriveSender1Pu(kwAlg string, apu, apv []byte, ephemeralPriv, senderPrivKey *ecdsa.PrivateKey,
		recPubKey *ecdsa.PublicKey, keySize int) ([]byte, error)
	deriveRecipient1Pu(kwAlg string, apu, apv []byte, ephemeralPub, senderPubKey *ecdsa.PublicKey,
		recPrivKey *ecdsa.PrivateKey, keySize int) ([]byte, error)
}

type keyWrapperSupport struct{}

func (w *keyWrapperSupport) getCurve(curve string) (elliptic.Curve, error) {
	return hybrid.GetCurve(curve)
}

func (w *keyWrapperSupport) generateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (w *keyWrapperSupport) createCipher(kek []byte) (cipher.Block, error) {
	return aes.NewCipher(kek)
}

func (w *keyWrapperSupport) wrap(block cipher.Block, cek []byte) ([]byte, error) {
	return josecipher.KeyWrap(block, cek)
}

func (w *keyWrapperSupport) unwrap(block cipher.Block, encryptedKey []byte) ([]byte, error) {
	return josecipher.KeyUnwrap(block, encryptedKey)
}

func (w *keyWrapperSupport) deriveSender1Pu(alg string, apu, apv []byte, ephemeralPriv, senderPrivKey *ecdsa.PrivateKey,
	recPubKey *ecdsa.PublicKey, keySize int) ([]byte, error) {
	ze := josecipher.DeriveECDHES(alg, apu, apv, ephemeralPriv, recPubKey, keySize)
	zs := josecipher.DeriveECDHES(alg, apu, apv, senderPrivKey, recPubKey, keySize)

	return derive1Pu(alg, ze, zs, apu, apv, keySize)
}

func (w *keyWrapperSupport) deriveRecipient1Pu(alg string, apu, apv []byte, ephemeralPub, senderPubKey *ecdsa.PublicKey,
	recPrivKey *ecdsa.PrivateKey, keySize int) ([]byte, error) {
	// DeriveECDHES checks if keys are on the same curve
	ze := josecipher.DeriveECDHES(alg, apu, apv, recPrivKey, ephemeralPub, keySize)
	zs := josecipher.DeriveECDHES(alg, apu, apv, recPrivKey, senderPubKey, keySize)

	return derive1Pu(alg, ze, zs, apu, apv, keySize)
}

func (t *Crypto) deriveKEKAndWrap(cek, apu, apv []byte, senderKH interface{}, ephemeralPrivKey *ecdsa.PrivateKey,
	recPubKey *ecdsa.PublicKey, recKID string) (*cryptoapi.RecipientWrappedKey, error) {
	var kek []byte

	// TODO: add support for 25519 key wrapping https://github.com/hyperledger/aries-framework-go/issues/1637
	keyType := ecdhpb.KeyType_EC.String()
	wrappingAlg := ECDHESA256KWAlg

	if senderKH != nil { // ecdh1pu
		wrappingAlg = ECDH1PUA256KWAlg

		senderPrivKey, err := ksToPrivateECDSAKey(senderKH)
		if err != nil {
			return nil, fmt.Errorf("wrapKey: failed to retrieve sender key: %w", err)
		}

		kek, err = t.kw.deriveSender1Pu(wrappingAlg, apu, apv, ephemeralPrivKey, senderPrivKey, recPubKey, defKeySize)
		if err != nil {
			return nil, fmt.Errorf("wrapKey: failed to derive key: %w", err)
		}
	} else { // ecdhes
		kek = josecipher.DeriveECDHES(wrappingAlg, apu, apv, ephemeralPrivKey, recPubKey, defKeySize)
	}

	block, err := t.kw.createCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to create new Cipher: %w", err)
	}

	wk, err := t.kw.wrap(block, cek)
	if err != nil {
		return nil, fmt.Errorf("wrapKey: failed to wrap key: %w", err)
	}

	return &cryptoapi.RecipientWrappedKey{
		KID:          recKID,
		EncryptedCEK: wk,
		EPK: cryptoapi.PublicKey{
			X:     ephemeralPrivKey.PublicKey.X.Bytes(),
			Y:     ephemeralPrivKey.PublicKey.Y.Bytes(),
			Curve: ephemeralPrivKey.PublicKey.Curve.Params().Name,
			Type:  keyType,
		},
		APU: apu,
		APV: apv,
		Alg: wrappingAlg,
	}, nil
}

func (t *Crypto) deriveKEKAndUnwrap(alg string, encCEK, apu, apv []byte, senderKH interface{},
	epkPubKey *ecdsa.PublicKey, recPrivKey *ecdsa.PrivateKey) ([]byte, error) {
	var kek []byte

	switch alg {
	case ECDH1PUA256KWAlg:
		if senderKH == nil {
			return nil, fmt.Errorf("unwrap: sender's public keyset handle option is required for "+
				"'%s'", ECDH1PUA256KWAlg)
		}

		senderPubKey, err := ksToPublicECDSAKey(senderKH, t.kw)
		if err != nil {
			return nil, fmt.Errorf("unwrapKey: failed to retrieve sender key: %w", err)
		}

		kek, err = t.kw.deriveRecipient1Pu(alg, apu, apv, epkPubKey, senderPubKey, recPrivKey, defKeySize)
		if err != nil {
			return nil, fmt.Errorf("unwrapKey: failed to derive kek: %w", err)
		}
	case ECDHESA256KWAlg:
		kek = josecipher.DeriveECDHES(alg, apu, apv, recPrivKey, epkPubKey, defKeySize)
	default:
		return nil, fmt.Errorf("unwrapKey: unsupported JWE KW Alg '%s'", alg)
	}

	block, err := t.kw.createCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("unwrapKey: failed to create new Cipher: %w", err)
	}

	wk, err := t.kw.unwrap(block, encCEK)
	if err != nil {
		return nil, fmt.Errorf("unwrapKey: failed to unwrap key: %w", err)
	}

	return wk, nil
}

func derive1Pu(kwAlg string, ze, zs, apu, apv []byte, keySize int) ([]byte, error) {
	z := append(ze, zs...)
	algID := cryptoutil.LengthPrefix([]byte(kwAlg))
	ptyUInfo := cryptoutil.LengthPrefix(apu)
	ptyVInfo := cryptoutil.LengthPrefix(apv)

	supPubLen := 4
	supPubInfo := make([]byte, supPubLen)

	byteLen := 8
	binary.BigEndian.PutUint32(supPubInfo, uint32(keySize)*uint32(byteLen))

	reader := josecipher.NewConcatKDF(crypto.SHA256, z, algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})

	kek := make([]byte, keySize)

	_, err := reader.Read(kek)
	if err != nil {
		return nil, err
	}

	return kek, nil
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

	return hybridECPrivToECDSAKey(senderHPrivKey), nil
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
	case *ecdsa.PublicKey:
		return kst, nil
	default:
		return nil, fmt.Errorf("ksToPublicECDSAKey: unsupported keyset type %+v", kst)
	}
}
