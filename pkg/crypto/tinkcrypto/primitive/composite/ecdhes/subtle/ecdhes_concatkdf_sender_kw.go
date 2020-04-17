/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/google/tink/go/subtle/hybrid"
	josecipher "github.com/square/go-jose/v3/cipher"
)

// A256KWAlg is the ECDH-ES key wrapping algorithm
const A256KWAlg = "ECDH-ES+A256KW"

// ECDHESConcatKDFSenderKW represents concat KDF based ECDH-ES KW (key wrapping)
// for ECDH-ES sender
type ECDHESConcatKDFSenderKW struct {
	recipientPublicKey *hybrid.ECPublicKey
	cek                []byte
}

// wrapKey will do ECDH-ES key wrapping
func (s *ECDHESConcatKDFSenderKW) wrapKey(kwAlg string, keySize int) (*RecipientWrappedKey, error) {
	recPubKey := &ecdsa.PublicKey{
		Curve: s.recipientPublicKey.Curve,
		X:     s.recipientPublicKey.Point.X,
		Y:     s.recipientPublicKey.Point.Y,
	}

	ephemeralPriv, err := ecdsa.GenerateKey(recPubKey.Curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	kek := josecipher.DeriveECDHES(kwAlg, []byte{}, []byte{}, ephemeralPriv, recPubKey, keySize)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	wk, err := josecipher.KeyWrap(block, s.cek)
	if err != nil {
		return nil, err
	}

	return &RecipientWrappedKey{
		EncryptedCEK: wk,
		EPK: ECPublicKey{
			X:     ephemeralPriv.PublicKey.X.Bytes(),
			Y:     ephemeralPriv.PublicKey.Y.Bytes(),
			Curve: ephemeralPriv.PublicKey.Curve.Params().Name,
		},
		Alg: kwAlg,
	}, nil
}
