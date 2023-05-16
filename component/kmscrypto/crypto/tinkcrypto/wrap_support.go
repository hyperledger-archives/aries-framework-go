/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	josecipher "github.com/go-jose/go-jose/v3/cipher"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
)

type keyWrapper interface {
	getCurve(curve string) (elliptic.Curve, error)
	generateKey(curve elliptic.Curve) (interface{}, error)
	createPrimitive(key []byte) (interface{}, error)
	wrap(blockPrimitive interface{}, cek []byte) ([]byte, error)
	unwrap(blockPrimitive interface{}, encryptedKey []byte) ([]byte, error)
	deriveSender1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPriv, senderPrivKey, recPubKey interface{},
		keySize int) ([]byte, error)
	deriveRecipient1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPub, senderPubKey, recPrivKey interface{},
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

func (w *ecKWSupport) deriveSender1Pu(alg string, apu, apv, tag []byte, ephemeralPriv, senderPrivKey interface{},
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

	ze := deriveECDH(ephemeralPrivEC, recPubKeyEC, keySize)
	zs := deriveECDH(senderPrivKeyEC, recPubKeyEC, keySize)

	return derive1Pu(alg, ze, zs, apu, apv, tag, keySize), nil
}

func (w *ecKWSupport) deriveRecipient1Pu(alg string, apu, apv, tag []byte, ephemeralPub, senderPubKey interface{},
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
	ze := deriveECDH(recPrivKeyEC, ephemeralPubEC, keySize)
	zs := deriveECDH(recPrivKeyEC, senderPubKeyEC, keySize)

	return derive1Pu(alg, ze, zs, apu, apv, tag, keySize), nil
}

const byteSize = 8

// deriveECDH does key derivation using ECDH only (without KDF).
func deriveECDH(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, size int) []byte {
	if size > 1<<16 {
		panic("ECDH-ES output size too large, must be less than or equal to 1<<16")
	}

	// suppPubInfo is the encoded length of the output size in bits
	supPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(supPubInfo, uint32(size)*byteSize)

	if !priv.PublicKey.Curve.IsOnCurve(pub.X, pub.Y) {
		panic("public key not on same curve as private key")
	}

	z, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	zBytes := z.Bytes()

	// Note that calling z.Bytes() on a big.Int may strip leading zero bytes from
	// the returned byte array. This can lead to a problem where zBytes will be
	// shorter than expected which breaks the key derivation. Therefore we must pad
	// to the full length of the expected coordinate here before calling the KDF.
	octSize := dSize(priv.Curve)
	if len(zBytes) != octSize {
		zBytes = append(bytes.Repeat([]byte{0}, octSize-len(zBytes)), zBytes...)
	}

	return zBytes
}

func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / byteSize

	if bitLen%byteSize != 0 {
		size++
	}

	return size
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

func (o *okpKWSupport) deriveSender1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPriv, senderPrivKey interface{},
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

	ze, err := cryptoutil.DeriveECDHX25519(ephemeralPrivOKPChacha, recPubKeyOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveSender1Pu: %w", err)
	}

	zs, err := cryptoutil.DeriveECDHX25519(senderPrivKeyOKPChacha, recPubKeyOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveSender1Pu: %w", err)
	}

	return derive1Pu(kwAlg, ze, zs, apu, apv, tag, chacha20poly1305.KeySize), nil
}

func (o *okpKWSupport) deriveRecipient1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPub, senderPubKey interface{},
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

	ze, err := cryptoutil.DeriveECDHX25519(recPrivKeyOKPChacha, ephemeralPubOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveRecipient1Pu: %w", err)
	}

	zs, err := cryptoutil.DeriveECDHX25519(recPrivKeyOKPChacha, senderPubKeyOKPChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveRecipient1Pu: %w", err)
	}

	return derive1Pu(kwAlg, ze, zs, apu, apv, tag, chacha20poly1305.KeySize), nil
}

func derive1Pu(kwAlg string, ze, zs, apu, apv, tag []byte, keySize int) []byte {
	z := append([]byte{}, ze...)
	z = append(z, zs...)

	return kdfWithTag(kwAlg, z, apu, apv, tag, keySize, true)
}

func kdf(kwAlg string, z, apu, apv []byte, keySize int) []byte {
	return kdfWithTag(kwAlg, z, apu, apv, nil, keySize, false)
}

func kdfWithTag(kwAlg string, z, apu, apv, tag []byte, keySize int, useTag bool) []byte {
	algID := cryptoutil.LengthPrefix([]byte(kwAlg))
	ptyUInfo := cryptoutil.LengthPrefix(apu)
	ptyVInfo := cryptoutil.LengthPrefix(apv)

	supPubLen := 4
	supPubInfo := make([]byte, supPubLen)

	byteLen := 8
	kdfKeySize := keySize

	switch kwAlg {
	case ECDH1PUA128KWAlg:
		kdfKeySize = subtle.AES128Size
	case ECDH1PUA192KWAlg:
		kdfKeySize = subtle.AES192Size
	case ECDH1PUA256KWAlg:
		kdfKeySize = subtle.AES256Size
	}

	binary.BigEndian.PutUint32(supPubInfo, uint32(kdfKeySize)*uint32(byteLen))

	if useTag {
		// append Tag to SuppPubInfo as described here:
		// https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.3
		tagInfo := cryptoutil.LengthPrefix(tag)
		supPubInfo = append(supPubInfo, tagInfo...)
	}

	reader := josecipher.NewConcatKDF(crypto.SHA256, z, algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})

	kek := make([]byte, kdfKeySize)

	_, _ = reader.Read(kek) // nolint:errcheck // ConcatKDF's Read() never returns an error

	return kek
}
