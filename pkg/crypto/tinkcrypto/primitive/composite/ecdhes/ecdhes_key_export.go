/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	commonpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

// PubKeyWriter will write the raw bytes of a Tink KeySet's primary public key. The raw bytes are a marshaled
// ecdhessubtle.PublicKey type.
// The keyset must have a keyURL value equal to `ecdhesAESPublicKeyTypeURL` constant of this package
// Note: This writer should be used only for ECDHES public key export. Other export of public keys should be called
//       via localkms package.
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
	var marshaledPubKey []byte

	switch key.KeyData.TypeUrl {
	case ecdhesAESPublicKeyTypeURL:
		pubKeyProto := new(ecdhespb.EcdhesAeadPublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, err
		}

		curveName := pubKeyProto.Params.KwParams.CurveType.String()
		keyTypeName := pubKeyProto.Params.KwParams.KeyType.String()

		// validate key type
		if pubKeyProto.Params.KwParams.KeyType != commonpb.KeyType_EC {
			return false, fmt.Errorf("undefined key type: '%s'", pubKeyProto.Params.KwParams.KeyType)
		}

		// validate curve
		_, err = hybrid.GetCurve(curveName)
		if err != nil {
			return false, fmt.Errorf("undefined curve: %w", err)
		}

		pubKey := composite.PublicKey{
			KID:   pubKeyProto.KID,
			Type:  keyTypeName,
			Curve: curveName,
			X:     pubKeyProto.X,
			Y:     pubKeyProto.Y,
		}

		marshaledPubKey, err = json.Marshal(pubKey)
		if err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("can't export key with keyURL:%s", key.KeyData.TypeUrl)
	}

	n, err := w.Write(marshaledPubKey)
	if err != nil {
		return false, nil
	}

	return n > 0, nil
}
