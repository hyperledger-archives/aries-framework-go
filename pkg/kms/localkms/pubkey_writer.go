/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/subtle"
	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	ed25519pb "github.com/google/tink/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	ecdsaVerifierTypeURL   = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
	ed25519VerifierTypeURL = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
)

// PubKeyWriter will write the raw bytes of a Tink KeySet's primary public key
// The keyset must be one of the keyURLs defined above
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
			switch key.KeyData.TypeUrl {
			case ecdsaVerifierTypeURL, ed25519VerifierTypeURL:
				created, err = writePubKey(w, key)
				if err != nil {
					return err
				}
			default:
				return fmt.Errorf("key type not supported for writing raw key bytes: %s", key.KeyData.TypeUrl)
			}

			break
		}
	}

	if !created {
		return fmt.Errorf("JWK not created")
	}

	return nil
}

func writePubKey(w io.Writer, key *tinkpb.Keyset_Key) (bool, error) {
	var marshaledPubKey []byte

	switch key.KeyData.TypeUrl {
	case ecdsaVerifierTypeURL:
		pubKeyProto := new(ecdsapb.EcdsaPublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, err
		}

		curveName := commonpb.EllipticCurveType_name[int32(pubKeyProto.Params.Curve)]

		curve := subtle.GetCurve(curveName)
		if curve == nil {
			return false, fmt.Errorf("undefined curve")
		}

		pubKey := ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		}

		pubKey.X.SetBytes(pubKeyProto.X)
		pubKey.Y.SetBytes(pubKeyProto.Y)

		marshaledPubKey = elliptic.Marshal(curve, pubKey.X, pubKey.Y)
	case ed25519VerifierTypeURL:
		pubKeyProto := new(ed25519pb.Ed25519PublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, err
		}

		marshaledPubKey = make([]byte, len(pubKeyProto.KeyValue))
		copy(marshaledPubKey, pubKeyProto.KeyValue)
	default:
		return false, fmt.Errorf("can't export key with keyURL:%s", key.KeyData.TypeUrl)
	}

	n, err := w.Write(marshaledPubKey)
	if err != nil {
		return false, nil
	}

	return n > 0, nil
}
