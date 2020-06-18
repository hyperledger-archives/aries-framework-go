/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keyio

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	commonpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdh1pupb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh1pu_aead_go_proto"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

// Package keyio supports exporting of Composite keys (aka Write) and converting the public key part of the a composite
// key (aka PublicKeyToHandle to be used as a valid Tink key)

const (
	ecdhesAESPublicKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.EcdhesAesAeadPublicKey"
	ecdh1puAESPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.Ecdh1puAesAeadPublicKey"
)

// PubKeyWriter will write the raw bytes of a Tink KeySet's primary public key. The raw bytes are a marshaled
// composite.PublicKey type.
// The keyset must have a keyURL value equal to `ecdhesAESPublicKeyTypeURL` constant of ecdhes package or
// `ecdh1puAESPublicKeyTypeURL` constant of ecdh1pu package.
// Note: This writer should be used only for ECDHES/ECDH1PU public key exports. Other export of public keys should be
//       called via localkms package.
type PubKeyWriter struct {
	w io.Writer
}

// NewWriter creates a new PubKeyWriter instance
func NewWriter(w io.Writer) *PubKeyWriter {
	return &PubKeyWriter{
		w: w,
	}
}

// Write writes the public keyset to the underlying w.Writer.
func (p *PubKeyWriter) Write(keyset *tinkpb.Keyset) error {
	return write(p.w, keyset)
}

// WriteEncrypted writes the encrypted keyset to the underlying w.Writer.
func (p *PubKeyWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	return fmt.Errorf("write encrypted function not supported")
}

func write(w io.Writer, msg *tinkpb.Keyset) error {
	ks := msg.Key
	primaryKID := msg.PrimaryKeyId
	created := false

	var err error

	for _, key := range ks {
		if key.KeyId == primaryKID && key.Status == tinkpb.KeyStatusType_ENABLED {
			created, err = writePubKey(w, key)
			if err != nil {
				return err
			}

			break
		}
	}

	if !created {
		return fmt.Errorf("key not written")
	}

	return nil
}

func writePubKey(w io.Writer, key *tinkpb.Keyset_Key) (bool, error) {
	pubKey, err := protoToCompositeKey(key.KeyData)
	if err != nil {
		return false, err
	}

	mPubKey, err := json.Marshal(pubKey)
	if err != nil {
		return false, err
	}

	n, err := w.Write(mPubKey)
	if err != nil {
		return false, err
	}

	return n > 0, nil
}

func protoToCompositeKey(keyData *tinkpb.KeyData) (*composite.PublicKey, error) {
	var (
		cKey compositeKeyGetter
		err  error
	)

	switch keyData.TypeUrl {
	case ecdhesAESPublicKeyTypeURL:
		cKey, err = newECDHESKey(keyData.Value)
		if err != nil {
			return nil, err
		}
	case ecdh1puAESPublicKeyTypeURL:
		cKey, err = newECDH1PUKey(keyData.Value)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("can't export key with keyURL:%s", keyData.TypeUrl)
	}

	return buildKey(cKey)
}

func buildKey(c compositeKeyGetter) (*composite.PublicKey, error) {
	curveName := c.curveName()
	keyTypeName := c.keyType()

	return buildCompositeKey(c.kid(), keyTypeName, curveName, c.x(), c.y())
}

func buildCompositeKey(kid, keyType, curve string, x, y []byte) (*composite.PublicKey, error) {
	// validate curve
	_, err := hybrid.GetCurve(curve)
	if err != nil {
		return nil, fmt.Errorf("undefined curve: %w", err)
	}

	return &composite.PublicKey{
		KID:   kid,
		Type:  keyType,
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

type compositeKeyGetter interface {
	kid() string
	curveName() string
	keyType() string
	x() []byte
	y() []byte
}

type ecdhesKey struct {
	protoKey *ecdhespb.EcdhesAeadPublicKey
}

func newECDHESKey(mKey []byte) (compositeKeyGetter, error) {
	pubKeyProto := new(ecdhespb.EcdhesAeadPublicKey)

	err := proto.Unmarshal(mKey, pubKeyProto)
	if err != nil {
		return nil, err
	}

	// validate key type
	if pubKeyProto.Params.KwParams.KeyType != commonpb.KeyType_EC {
		return nil, fmt.Errorf("undefined key type: '%s'", pubKeyProto.Params.KwParams.KeyType)
	}

	return &ecdhesKey{protoKey: pubKeyProto}, nil
}

func (e *ecdhesKey) kid() string {
	return e.protoKey.KID
}

func (e *ecdhesKey) curveName() string {
	return e.protoKey.Params.KwParams.CurveType.String()
}

func (e *ecdhesKey) keyType() string {
	return e.protoKey.Params.KwParams.KeyType.String()
}

func (e *ecdhesKey) x() []byte {
	return e.protoKey.X
}

func (e *ecdhesKey) y() []byte {
	return e.protoKey.Y
}

type ecdh1puKey struct {
	protoKey *ecdh1pupb.Ecdh1PuAeadPublicKey
}

func newECDH1PUKey(mKey []byte) (compositeKeyGetter, error) {
	pubKeyProto := new(ecdh1pupb.Ecdh1PuAeadPublicKey)

	err := proto.Unmarshal(mKey, pubKeyProto)
	if err != nil {
		return nil, err
	}

	// validate key type
	if pubKeyProto.Params.KwParams.KeyType != commonpb.KeyType_EC {
		return nil, fmt.Errorf("undefined key type: '%s'", pubKeyProto.Params.KwParams.KeyType)
	}

	return &ecdh1puKey{protoKey: pubKeyProto}, nil
}

func (e *ecdh1puKey) kid() string {
	return e.protoKey.KID
}

func (e *ecdh1puKey) curveName() string {
	return e.protoKey.Params.KwParams.CurveType.String()
}

func (e *ecdh1puKey) keyType() string {
	return e.protoKey.Params.KwParams.KeyType.String()
}

func (e *ecdh1puKey) x() []byte {
	return e.protoKey.X
}

func (e *ecdh1puKey) y() []byte {
	return e.protoKey.Y
}
