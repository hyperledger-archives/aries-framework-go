/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"
	josecipher "github.com/square/go-jose/v3/cipher"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

// A256KWAlg is the ECDH-1PU key wrapping algorithm.
const A256KWAlg = "ECDH-1PU+A256KW"

// ECDH1PUConcatKDFSenderKW represents concat KDF based ECDH-1PU KW (key wrapping)
// for ECDH-1PU sender.
type ECDH1PUConcatKDFSenderKW struct {
	senderPrivateKey   *hybrid.ECPrivateKey
	recipientPublicKey *composite.PublicKey
	cek                []byte
}

// wrapKey will do ECDH-1PU key wrapping.
func (s *ECDH1PUConcatKDFSenderKW) wrapKey(kwAlg string, keySize int) (*composite.RecipientWrappedKey, error) {
	// TODO: add support for 25519 key wrapping https://github.com/hyperledger/aries-framework-go/issues/1637
	keyType := compositepb.KeyType_EC.String()

	c, err := hybrid.GetCurve(s.recipientPublicKey.Curve)
	if err != nil {
		return nil, err
	}

	if c != s.senderPrivateKey.PublicKey.Curve {
		return nil, fmt.Errorf("unwrapKey: recipient and sender keys are not on the same curve")
	}

	recPubKey := &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(s.recipientPublicKey.X),
		Y:     new(big.Int).SetBytes(s.recipientPublicKey.Y),
	}

	ephemeralPriv, err := ecdsa.GenerateKey(recPubKey.Curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	senderPriveKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: s.senderPrivateKey.PublicKey.Curve,
			X:     s.senderPrivateKey.PublicKey.Point.X,
			Y:     s.senderPrivateKey.PublicKey.Point.Y,
		},
		D: s.senderPrivateKey.D,
	}

	kek, err := deriveSender1Pu(kwAlg, ephemeralPriv, senderPriveKey, recPubKey, keySize)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	wk, err := josecipher.KeyWrap(block, s.cek)
	if err != nil {
		return nil, err
	}

	return &composite.RecipientWrappedKey{
		KID:          s.recipientPublicKey.KID,
		EncryptedCEK: wk,
		EPK: composite.PublicKey{
			X:     ephemeralPriv.PublicKey.X.Bytes(),
			Y:     ephemeralPriv.PublicKey.Y.Bytes(),
			Curve: ephemeralPriv.PublicKey.Curve.Params().Name,
			Type:  keyType,
		},
		Alg: kwAlg,
	}, nil
}

func deriveSender1Pu(kwAlg string, ephemeralPriv, senderPrivKey *ecdsa.PrivateKey, recPubKey *ecdsa.PublicKey,
	keySize int) ([]byte, error) {
	ze := josecipher.DeriveECDHES(kwAlg, []byte{}, []byte{}, ephemeralPriv, recPubKey, keySize)
	zs := josecipher.DeriveECDHES(kwAlg, []byte{}, []byte{}, senderPrivKey, recPubKey, keySize)

	return derive1Pu(kwAlg, ze, zs, keySize)
}

func derive1Pu(kwAlg string, ze, zs []byte, keySize int) ([]byte, error) {
	z := append(ze, zs...)
	algID := cryptoutil.LengthPrefix([]byte(kwAlg))
	ptyUInfo := cryptoutil.LengthPrefix([]byte{})
	ptyVInfo := cryptoutil.LengthPrefix([]byte{})

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
