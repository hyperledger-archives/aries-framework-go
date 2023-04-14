/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

func extractPrivKey(kh *keyset.Handle) (interface{}, error) {
	buf := new(bytes.Buffer)
	w := &privKeyWriter{w: buf}
	nAEAD := &noopAEAD{}

	if kh == nil {
		return nil, fmt.Errorf("extractPrivKey: kh is nil")
	}

	err := kh.Write(w, nAEAD)
	if err != nil {
		return nil, fmt.Errorf("extractPrivKey: retrieving private key failed: %w", err)
	}

	ks := new(tinkpb.Keyset)

	err = proto.Unmarshal(buf.Bytes(), ks)
	if err != nil {
		return nil, errors.New("extractPrivKey: invalid private key")
	}

	primaryKey := ks.Key[0]

	switch primaryKey.KeyData.TypeUrl {
	case nistPECDHKWPrivateKeyTypeURL:
		pbKey := new(ecdhpb.EcdhAeadPrivateKey)

		err = proto.Unmarshal(primaryKey.KeyData.Value, pbKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid key in keyset")
		}

		var c elliptic.Curve

		c, err = hybrid.GetCurve(pbKey.PublicKey.Params.KwParams.CurveType.String())
		if err != nil {
			return nil, fmt.Errorf("extractPrivKey: invalid key: %w", err)
		}

		return hybrid.GetECPrivateKey(c, pbKey.KeyValue), nil
	case x25519ECDHKWPrivateKeyTypeURL:
		pbKey := new(ecdhpb.EcdhAeadPrivateKey)

		err = proto.Unmarshal(primaryKey.KeyData.Value, pbKey)
		if err != nil {
			return nil, errors.New("extractPrivKey: invalid key in keyset")
		}

		if pbKey.PublicKey.Params.KwParams.CurveType.String() != commonpb.EllipticCurveType_CURVE25519.String() {
			return nil, errors.New("extractPrivKey: invalid key curve")
		}

		return pbKey.KeyValue, nil
	}

	return nil, fmt.Errorf("extractPrivKey: can't extract unsupported private key '%s'", primaryKey.KeyData.TypeUrl)
}

func hybridECPrivToECDSAKey(hybridEcPriv *hybrid.ECPrivateKey) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: hybridEcPriv.PublicKey.Curve,
			X:     hybridEcPriv.PublicKey.Point.X,
			Y:     hybridEcPriv.PublicKey.Point.Y,
		},
		D: hybridEcPriv.D,
	}
}

type noopAEAD struct{}

func (n noopAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	return plaintext, nil
}

func (n noopAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	return ciphertext, nil
}

type privKeyWriter struct {
	w io.Writer
}

// Write writes the public keyset to the underlying w.Writer. It's not used in this implementation.
func (p *privKeyWriter) Write(_ *tinkpb.Keyset) error {
	return fmt.Errorf("privKeyWriter: write function not supported")
}

// WriteEncrypted writes the encrypted keyset to the underlying w.Writer.
func (p *privKeyWriter) WriteEncrypted(ks *tinkpb.EncryptedKeyset) error {
	return write(p.w, ks)
}

func write(w io.Writer, ks *tinkpb.EncryptedKeyset) error {
	// we write EncryptedKeyset directly without decryption since noopAEAD was used to write *keyset.Handle
	_, e := w.Write(ks.EncryptedKeyset)
	return e
}
