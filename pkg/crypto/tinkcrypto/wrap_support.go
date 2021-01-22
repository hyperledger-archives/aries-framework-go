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
	"errors"
	"fmt"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	josecipher "github.com/square/go-jose/v3/cipher"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

type keyWrapper interface {
	getCurve(curve string) (elliptic.Curve, error)
	generateKey(curve elliptic.Curve) (interface{}, error)
	createPrimitive(key []byte) (interface{}, error)
	wrap(blockPrimitive interface{}, cek []byte) ([]byte, error)
	unwrap(blockPrimitive interface{}, encryptedKey []byte) ([]byte, error)
	deriveSender1Pu(kwAlg string, apu, apv []byte, ephemeralPriv, senderPrivKey, recPubKey interface{},
		keySize int) ([]byte, error)
	deriveRecipient1Pu(kwAlg string, apu, apv []byte, ephemeralPub, senderPubKey, recPrivKey interface{},
		keySize int) ([]byte, error)
}

type ecKWSupport struct{}

func (w *ecKWSupport) getCurve(curve string) (elliptic.Curve, error) {
	return hybrid.GetCurve(curve)
}

func (w *ecKWSupport) generateKey(curve elliptic.Curve) (interface{}, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (w *ecKWSupport) createPrimitive(kek []byte) (interface{}, error) {
	return aes.NewCipher(kek)
}

func (w *ecKWSupport) wrap(block interface{}, cek []byte) ([]byte, error) {
	blockCipher, ok := block.(cipher.Block)
	if !ok {
		return nil, errors.New("wrap support: EC wrap with invalid cipher block type")
	}

	return josecipher.KeyWrap(blockCipher, cek)
}

func (w *ecKWSupport) unwrap(block interface{}, encryptedKey []byte) ([]byte, error) {
	blockCipher, ok := block.(cipher.Block)
	if !ok {
		return nil, errors.New("unwrap support: EC wrap with invalid cipher block type")
	}

	return josecipher.KeyUnwrap(blockCipher, encryptedKey)
}

func (w *ecKWSupport) deriveSender1Pu(alg string, apu, apv []byte, ephemeralPriv, senderPrivKey interface{},
	recPubKey interface{}, keySize int) ([]byte, error) {
	ephemeralPrivEC, ok := ephemeralPriv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("deriveSender1Pu: ephemeral key not ECDSA type")
	}

	senderPrivKeyEC, ok := senderPrivKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("deriveSender1Pu: sender key not ECDSA type")
	}

	recPubKeyEC, ok := recPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("deriveSender1Pu: recipient key not ECDSA type")
	}

	if recPubKeyEC.Curve != ephemeralPrivEC.Curve || recPubKeyEC.Curve != senderPrivKeyEC.Curve {
		return nil, errors.New("deriveSender1Pu: recipient, sender and ephemeral key are not on the same curve")
	}

	ze := josecipher.DeriveECDHES(alg, apu, apv, ephemeralPrivEC, recPubKeyEC, keySize)
	zs := josecipher.DeriveECDHES(alg, apu, apv, senderPrivKeyEC, recPubKeyEC, keySize)

	return derive1Pu(alg, ze, zs, apu, apv, keySize), nil
}

func (w *ecKWSupport) deriveRecipient1Pu(alg string, apu, apv []byte, ephemeralPub, senderPubKey interface{},
	recPrivKey interface{}, keySize int) ([]byte, error) {
	ephemeralPubEC, ok := ephemeralPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("deriveRecipient1Pu: ephemeral key not ECDSA type")
	}

	senderPubKeyEC, ok := senderPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("deriveRecipient1Pu: sender key not ECDSA type")
	}

	recPrivKeyEC, ok := recPrivKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("deriveRecipient1Pu: recipient key not ECDSA type")
	}

	if recPrivKeyEC.Curve != ephemeralPubEC.Curve || recPrivKeyEC.Curve != senderPubKeyEC.Curve {
		return nil, errors.New("deriveRecipient1Pu: recipient, sender and ephemeral key are not on the same curve")
	}

	// DeriveECDHES checks if keys are on the same curve
	ze := josecipher.DeriveECDHES(alg, apu, apv, recPrivKeyEC, ephemeralPubEC, keySize)
	zs := josecipher.DeriveECDHES(alg, apu, apv, recPrivKeyEC, senderPubKeyEC, keySize)

	return derive1Pu(alg, ze, zs, apu, apv, keySize), nil
}

type okpKWSupport struct{}

func (o *okpKWSupport) getCurve(curve string) (elliptic.Curve, error) {
	return nil, errors.New("getCurve: not implemented for OKP KW support")
}

func (o *okpKWSupport) generateKey(_ elliptic.Curve) (interface{}, error) {
	newKey := make([]byte, cryptoutil.Curve25519KeySize)

	_, err := rand.Read(newKey)
	if err != nil {
		return nil, fmt.Errorf("generateKey: failed to create X25519 random key: %w", err)
	}

	return newKey, nil
}

func (o *okpKWSupport) createPrimitive(kek []byte) (interface{}, error) {
	p, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("createPrimitive: failed to create OKP primitive: %w", err)
	}

	return p, nil
}

func (o *okpKWSupport) wrap(aead interface{}, cek []byte) ([]byte, error) {
	aeadPrimitive, ok := aead.(cipher.AEAD)
	if !ok {
		return nil, errors.New("wrap support: OKP wrap with invalid primitive type")
	}

	nonceSize := aeadPrimitive.NonceSize()
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("wrap support: failed to generate random nonce: %w", err)
	}

	cipherText := aeadPrimitive.Seal(nil, nonce, cek, nil)

	return append(nonce, cipherText...), nil
}

func (o *okpKWSupport) unwrap(aead interface{}, encryptedKey []byte) ([]byte, error) {
	aeadPrimitive, ok := aead.(cipher.AEAD)
	if !ok {
		return nil, errors.New("unwrap support: OKP unwrap with invalid primitive type")
	}

	if len(encryptedKey) < aeadPrimitive.NonceSize() {
		return nil, errors.New("unwrap support: OKP unwrap invalid key")
	}

	nonce := encryptedKey[:aeadPrimitive.NonceSize()]

	cek, err := aeadPrimitive.Open(nil, nonce, encryptedKey[aeadPrimitive.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap support: OKP failed to unwrap key: %w", err)
	}

	return cek, nil
}

func (o *okpKWSupport) deriveSender1Pu(kwAlg string, apu, apv []byte, ephemeralPriv, senderPrivKey interface{},
	recPubKey interface{}, _ int) ([]byte, error) {
	ephemeralPrivOKP, ok := ephemeralPriv.([]byte)
	if !ok {
		return nil, errors.New("deriveSender1Pu: ephemeral key not OKP type")
	}

	ephemeralPrivOKPChacha := new([chacha20poly1305.KeySize]byte)
	copy(ephemeralPrivOKPChacha[:], ephemeralPrivOKP)

	senderPrivKeyOKP, ok := senderPrivKey.([]byte)
	if !ok {
		return nil, errors.New("deriveSender1Pu: sender key not OKP type")
	}

	senderPrivKeyOKPChacha := new([chacha20poly1305.KeySize]byte)
	copy(senderPrivKeyOKPChacha[:], senderPrivKeyOKP)

	recPubKeyOKP, ok := recPubKey.([]byte)
	if !ok {
		return nil, errors.New("deriveSender1Pu: recipient key not OKP type")
	}

	recPubKeyOKPChacha := new([chacha20poly1305.KeySize]byte)
	copy(recPubKeyOKPChacha[:], recPubKeyOKP)

	ze, err := cryptoutil.Derive25519KEK([]byte(kwAlg), apu, apv, ephemeralPrivOKPChacha, recPubKeyOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveSender1Pu: derive25519KEK with ephemeral key failed: %w", err)
	}

	zs, err := cryptoutil.Derive25519KEK([]byte(kwAlg), apu, apv, senderPrivKeyOKPChacha, recPubKeyOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveSender1Pu: derive25519KEK with sender key failed: %w", err)
	}

	return derive1Pu(kwAlg, ze, zs, apu, apv, chacha20poly1305.KeySize), nil
}

func (o *okpKWSupport) deriveRecipient1Pu(kwAlg string, apu, apv []byte, ephemeralPub, senderPubKey interface{},
	recPrivKey interface{}, _ int) ([]byte, error) {
	ephemeralPubOKP, ok := ephemeralPub.([]byte)
	if !ok {
		return nil, errors.New("deriveRecipient1Pu: ephemeral key not OKP type")
	}

	ephemeralPubOKPChacha := new([chacha20poly1305.KeySize]byte)
	copy(ephemeralPubOKPChacha[:], ephemeralPubOKP)

	senderPubKeyOKP, ok := senderPubKey.([]byte)
	if !ok {
		return nil, errors.New("deriveRecipient1Pu: sender key not OKP type")
	}

	senderPubKeyOKPChacha := new([chacha20poly1305.KeySize]byte)
	copy(senderPubKeyOKPChacha[:], senderPubKeyOKP)

	recPrivKeyOKP, ok := recPrivKey.([]byte)
	if !ok {
		return nil, errors.New("deriveRecipient1Pu: recipient key not OKP type")
	}

	recPrivKeyOKPChacha := new([chacha20poly1305.KeySize]byte)
	copy(recPrivKeyOKPChacha[:], recPrivKeyOKP)

	ze, err := cryptoutil.Derive25519KEK([]byte(kwAlg), apu, apv, recPrivKeyOKPChacha, ephemeralPubOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveRecipient1Pu: derive25519KEK with ephemeral key failed: %w", err)
	}

	zs, err := cryptoutil.Derive25519KEK([]byte(kwAlg), apu, apv, recPrivKeyOKPChacha, senderPubKeyOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveRecipient1Pu: derive25519KEK with sender key failed: %w", err)
	}

	return derive1Pu(kwAlg, ze, zs, apu, apv, chacha20poly1305.KeySize), nil
}

func derive1Pu(kwAlg string, ze, zs, apu, apv []byte, keySize int) []byte {
	round1 := make([]byte, 4)
	binary.BigEndian.PutUint32(round1, uint32(1))

	// 1PU requires round one number (0001) to be prefixed to the Z concatenation
	z := append(round1, ze...)
	z = append(z, zs...)

	algID := cryptoutil.LengthPrefix([]byte(kwAlg))
	ptyUInfo := cryptoutil.LengthPrefix(apu)
	ptyVInfo := cryptoutil.LengthPrefix(apv)

	supPubLen := 4
	supPubInfo := make([]byte, supPubLen)

	byteLen := 8
	binary.BigEndian.PutUint32(supPubInfo, uint32(keySize)*uint32(byteLen))

	reader := josecipher.NewConcatKDF(crypto.SHA256, z, algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})

	kek := make([]byte, keySize)

	_, _ = reader.Read(kek) // nolint:errcheck // ConcatKDF's Read() never returns an error

	return kek
}
