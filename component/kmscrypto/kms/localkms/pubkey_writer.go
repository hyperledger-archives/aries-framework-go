/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"

	"github.com/golang/protobuf/proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	secp256k1subtle "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
)

const (
	ecdsaVerifierTypeURL         = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
	ed25519VerifierTypeURL       = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
	nistPECDHKWPublicKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey"
	x25519ECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey"
	bbsVerifierKeyTypeURL        = "type.hyperledger.org/hyperledger.aries.crypto.tink.BBSPublicKey"
	clCredDefKeyTypeURL          = "type.hyperledger.org/hyperledger.aries.crypto.tink.CLCredDefKey"
	secp256k1VerifierTypeURL     = "type.googleapis.com/google.crypto.tink.secp256k1PublicKey"
	derPrefix                    = "der-"
	p13163Prefix                 = "p1363-"
)

//nolint:gochecknoglobals
var ecdsaKMSKeyTypes = map[string]kms.KeyType{
	derPrefix + "NIST_P256":    kms.ECDSAP256TypeDER,
	derPrefix + "NIST_P384":    kms.ECDSAP384TypeDER,
	derPrefix + "NIST_P521":    kms.ECDSAP521TypeDER,
	derPrefix + "SECP256K1":    kms.ECDSASecp256k1DER,
	p13163Prefix + "NIST_P256": kms.ECDSAP256TypeIEEEP1363,
	p13163Prefix + "NIST_P384": kms.ECDSAP384TypeIEEEP1363,
	p13163Prefix + "NIST_P521": kms.ECDSAP521TypeIEEEP1363,
	p13163Prefix + "SECP256K1": kms.ECDSASecp256k1IEEEP1363,
}

// PubKeyWriter will write the raw bytes of a Tink KeySet's primary public key
// The keyset must be one of the keyURLs defined above
// Note: Only signing public keys and ecdh key types created in tinkcrypto can be exported through this PubKeyWriter.
// ECHDES has its own Writer to export its public keys due to cyclic dependency.
type PubKeyWriter struct {
	// KeyType is Key Type of the written key. It's needed as Write() is an interface function and can't return it.
	KeyType kms.KeyType
	w       io.Writer
}

// NewWriter creates a new PubKeyWriter instance.
func NewWriter(w io.Writer) *PubKeyWriter {
	return &PubKeyWriter{
		w: w,
	}
}

// Write writes the public keyset to the underlying w.Writer.
func (p *PubKeyWriter) Write(keyset *tinkpb.Keyset) error {
	keyType, err := write(p.w, keyset)
	if err != nil {
		return err
	}

	p.KeyType = keyType

	return nil
}

// WriteEncrypted writes the encrypted keyset to the underlying w.Writer.
func (p *PubKeyWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	return fmt.Errorf("write encrypted function not supported")
}

func write(w io.Writer, msg *tinkpb.Keyset) (kms.KeyType, error) {
	ks := msg.Key
	primaryKID := msg.PrimaryKeyId
	created := false

	var (
		kt  kms.KeyType
		err error
	)

	for _, key := range ks {
		if key.KeyId == primaryKID && key.Status == tinkpb.KeyStatusType_ENABLED {
			switch key.KeyData.TypeUrl {
			case ecdsaVerifierTypeURL, ed25519VerifierTypeURL, bbsVerifierKeyTypeURL, clCredDefKeyTypeURL,
				secp256k1VerifierTypeURL:
				created, kt, err = writePubKey(w, key)
				if err != nil {
					return "", err
				}
			case nistPECDHKWPublicKeyTypeURL, x25519ECDHKWPublicKeyTypeURL:
				pkW := keyio.NewWriter(w)

				err = pkW.Write(msg)
				if err != nil {
					return "", err
				}

				kt = pkW.KeyType
				created = true
			default:
				return "", fmt.Errorf("key type not supported for writing raw key bytes: %s", key.KeyData.TypeUrl)
			}

			break
		}
	}

	if !created {
		return "", fmt.Errorf("key not written")
	}

	return kt, nil
}

// nolint:gocyclo,funlen
func writePubKey(w io.Writer, key *tinkpb.Keyset_Key) (bool, kms.KeyType, error) {
	var (
		marshaledRawPubKey []byte
		kt                 kms.KeyType
	)

	// TODO add other key types than the ones below and other than nistPECDHKWPublicKeyTypeURL and
	// TODO x25519ECDHKWPublicKeyTypeURL(eg: secp256k1 when introduced in KMS).
	switch key.KeyData.TypeUrl {
	case ecdsaVerifierTypeURL:
		pubKeyProto := new(ecdsapb.EcdsaPublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}

		marshaledRawPubKey, kt, err = getMarshalledECDSAKeyValueFromProto(pubKeyProto)
		if err != nil {
			return false, "", err
		}
	case ed25519VerifierTypeURL:
		pubKeyProto := new(ed25519pb.Ed25519PublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}

		marshaledRawPubKey = make([]byte, len(pubKeyProto.KeyValue))
		copy(marshaledRawPubKey, pubKeyProto.KeyValue)

		kt = kms.ED25519Type
	case bbsVerifierKeyTypeURL:
		pubKeyProto := new(bbspb.BBSPublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}

		marshaledRawPubKey = make([]byte, len(pubKeyProto.KeyValue))
		copy(marshaledRawPubKey, pubKeyProto.KeyValue)

		kt = kms.BLS12381G2Type
	case clCredDefKeyTypeURL:
		pubKeyProto := new(clpb.CLCredDefPublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}

		marshaledRawPubKey = make([]byte, len(pubKeyProto.KeyValue))
		copy(marshaledRawPubKey, pubKeyProto.KeyValue)

		kt = kms.CLCredDefType
	case secp256k1VerifierTypeURL:
		pubKeyProto := new(secp256k1pb.Secp256K1PublicKey)

		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}

		marshaledRawPubKey, kt, err = getMarshalledSecp256K1KeyValueFromProto(pubKeyProto)
		if err != nil {
			return false, "", err
		}
	default:
		return false, "", fmt.Errorf("can't export key with keyURL:%s", key.KeyData.TypeUrl)
	}

	n, err := w.Write(marshaledRawPubKey)
	if err != nil {
		return false, "", nil //nolint:nilerr
	}

	return n > 0, kt, nil
}

func getMarshalledECDSAKeyValueFromProto(pubKeyProto *ecdsapb.EcdsaPublicKey) ([]byte, kms.KeyType, error) {
	var (
		marshaledRawPubKey []byte
		err                error
		kt                 kms.KeyType
	)

	curveName := commonpb.EllipticCurveType_name[int32(pubKeyProto.Params.Curve)]

	curve := subtle.GetCurve(curveName)
	if curve == nil {
		return nil, "", fmt.Errorf("undefined curve")
	}

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int),
		Y:     new(big.Int),
	}

	pubKey.X.SetBytes(pubKeyProto.X)
	pubKey.Y.SetBytes(pubKeyProto.Y)

	switch pubKeyProto.Params.Encoding {
	case ecdsapb.EcdsaSignatureEncoding_DER:
		marshaledRawPubKey, err = x509.MarshalPKIXPublicKey(&pubKey) // DER format not supported here.
		if err != nil {
			return nil, "", err
		}

		kt = ecdsaKMSKeyTypes[derPrefix+curveName]
	case ecdsapb.EcdsaSignatureEncoding_IEEE_P1363:
		marshaledRawPubKey = elliptic.Marshal(curve, pubKey.X, pubKey.Y)
		kt = ecdsaKMSKeyTypes[p13163Prefix+curveName]
	default:
		return nil, "", fmt.Errorf("can't export key with bad key encoding: '%s'", pubKeyProto.Params.Encoding)
	}

	return marshaledRawPubKey, kt, nil
}

func getMarshalledSecp256K1KeyValueFromProto(pkPB *secp256k1pb.Secp256K1PublicKey) ([]byte, kms.KeyType, error) {
	var (
		marshaledRawPubKey []byte
		err                error
		kt                 kms.KeyType
	)

	curveName := secp256k1pb.BitcoinCurveType_name[int32(pkPB.Params.Curve)]

	curve := secp256k1subtle.GetCurve(curveName)
	if curve == nil {
		return nil, "", fmt.Errorf("undefined curve")
	}

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int),
		Y:     new(big.Int),
	}

	pubKey.X.SetBytes(pkPB.X)
	pubKey.Y.SetBytes(pkPB.Y)

	switch pkPB.Params.Encoding {
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER:
		marshaledRawPubKey, err = x509.MarshalPKIXPublicKey(&pubKey)
		if err != nil {
			return nil, "", err
		}

		kt = ecdsaKMSKeyTypes[derPrefix+curveName]
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363:
		marshaledRawPubKey = elliptic.Marshal(curve, pubKey.X, pubKey.Y)
		kt = ecdsaKMSKeyTypes[p13163Prefix+curveName]
	default:
		return nil, "", fmt.Errorf("can't export key with bad key encoding: '%s'", pkPB.Params.Encoding)
	}

	return marshaledRawPubKey, kt, nil
}
