/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	ed25519pb "github.com/google/tink/go/proto/ed25519_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	ecdsaSignerTypeURL   = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
	ed25519SignerTypeURL = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
)

func (l *LocalKMS) importECDSAKey(privKey *ecdsa.PrivateKey, kt kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	var params *ecdsapb.EcdsaParams

	err := validECPrivateKey(privKey)
	if err != nil {
		return "", nil, fmt.Errorf("import private EC key failed: %w", err)
	}

	switch kt {
	case kms.ECDSAP256TypeDER:
		params = &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			HashType: commonpb.HashType_SHA256,
		}
	case kms.ECDSAP384TypeDER:
		params = &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P384,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			HashType: commonpb.HashType_SHA512,
		}
	case kms.ECDSAP521TypeDER:
		params = &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P521,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
			HashType: commonpb.HashType_SHA512,
		}
	case kms.ECDSAP256TypeIEEEP1363:
		params = &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			HashType: commonpb.HashType_SHA256,
		}
	case kms.ECDSAP384TypeIEEEP1363:
		params = &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P384,
			Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			HashType: commonpb.HashType_SHA512,
		}
	case kms.ECDSAP521TypeIEEEP1363:
		params = &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P521,
			Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			HashType: commonpb.HashType_SHA512,
		}
	default:
		return "", nil, fmt.Errorf("import private EC key failed: invalid ECDSA key type")
	}

	mKeyValue, err := getMarshalledECDSAPrivateKey(privKey, params)
	if err != nil {
		return "", nil, fmt.Errorf("import private EC key failed: %w", err)
	}

	ks := newKeySet(ecdsaSignerTypeURL, mKeyValue, tinkpb.KeyData_ASYMMETRIC_PRIVATE)

	return l.importKeySet(ks, opts...)
}

func (l *LocalKMS) importKeySet(ks *tinkpb.Keyset, opts ...kms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	ksID, err := l.writeImportedKey(ks, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("import private EC key failed: %w", err)
	}

	kh, err := l.getKeySet(ksID)
	if err != nil {
		return ksID, nil, fmt.Errorf("import private EC key successful but failed to get key from store: %w", err)
	}

	return ksID, kh, nil
}

func getMarshalledECDSAPrivateKey(privKey *ecdsa.PrivateKey, params *ecdsapb.EcdsaParams) ([]byte, error) {
	pubKeyProto := newProtoECDSAPublicKey(&privKey.PublicKey, params)
	return proto.Marshal(newProtoECDSAPrivateKey(pubKeyProto, privKey.D.Bytes()))
}

func (l *LocalKMS) importEd25519Key(privKey ed25519.PrivateKey, kt kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	if privKey == nil {
		return "", nil, fmt.Errorf("import private ED25519 key failed: private key is nil")
	}

	if kt != kms.ED25519Type {
		return "", nil, fmt.Errorf("import private ED25519 key failed: invalid key type")
	}

	privKeyProto, err := newProtoEd25519PrivateKey(privKey)
	if err != nil {
		return "", nil, fmt.Errorf("import private ED25519 key failed: %w", err)
	}

	mKeyValue, err := proto.Marshal(privKeyProto)
	if err != nil {
		return "", nil, fmt.Errorf("import private ED25519 key failed: %w", err)
	}

	ks := newKeySet(ed25519SignerTypeURL, mKeyValue, tinkpb.KeyData_ASYMMETRIC_PRIVATE)

	return l.importKeySet(ks, opts...)
}

func validECPrivateKey(privateKey *ecdsa.PrivateKey) error {
	if privateKey == nil {
		return fmt.Errorf("private key is nil")
	}

	if privateKey.X == nil {
		return fmt.Errorf("private key's public key is missing x coordinate")
	}

	if privateKey.Y == nil {
		return fmt.Errorf("private key's public key is missing y coordinate")
	}

	if privateKey.D == nil {
		return fmt.Errorf("private key data is missing")
	}

	return nil
}

// newProtoECDSAPrivateKey creates a ECDSAPrivateKey with the specified parameters.
func newProtoECDSAPrivateKey(publicKey *ecdsapb.EcdsaPublicKey, keyValue []byte) *ecdsapb.EcdsaPrivateKey {
	return &ecdsapb.EcdsaPrivateKey{
		Version:   0,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

func newProtoEd25519PrivateKey(privateKey ed25519.PrivateKey) (*ed25519pb.Ed25519PrivateKey, error) {
	pubKey, ok := (privateKey.Public()).(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key from private key is not ed25519.PublicKey")
	}

	publicProto := &ed25519pb.Ed25519PublicKey{
		Version:  0,
		KeyValue: pubKey,
	}

	return &ed25519pb.Ed25519PrivateKey{
		Version:   0,
		PublicKey: publicProto,
		KeyValue:  privateKey.Seed(),
	}, nil
}

func (l *LocalKMS) writeImportedKey(ks *tinkpb.Keyset, opts ...kms.PrivateKeyOpts) (string, error) {
	serializedKeyset, err := proto.Marshal(ks)
	if err != nil {
		return "", fmt.Errorf("invalid keyset data")
	}

	encrypted, err := l.masterKeyEnvAEAD.Encrypt(serializedKeyset, []byte{})
	if err != nil {
		return "", fmt.Errorf("encrypted failed: %w", err)
	}

	ksInfo, err := getKeysetInfo(ks)
	if err != nil {
		return "", fmt.Errorf("cannot get keyset info: %w", err)
	}

	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      ksInfo,
	}

	buf := new(bytes.Buffer)
	jsonKeysetWriter := keyset.NewJSONWriter(buf)

	err = jsonKeysetWriter.WriteEncrypted(encryptedKeyset)
	if err != nil {
		return "", fmt.Errorf("failed to write keyset as json: %w", err)
	}

	return writeToStore(l.store, buf, opts...)
}

func getKeysetInfo(ks *tinkpb.Keyset) (*tinkpb.KeysetInfo, error) {
	if ks == nil {
		return nil, fmt.Errorf("keyset is nil")
	}

	var keyInfos []*tinkpb.KeysetInfo_KeyInfo

	for _, key := range ks.Key {
		info, err := getKeyInfo(key)
		if err != nil {
			return nil, err
		}

		keyInfos = append(keyInfos, info)
	}

	return &tinkpb.KeysetInfo{
		PrimaryKeyId: ks.PrimaryKeyId,
		KeyInfo:      keyInfos,
	}, nil
}

func getKeyInfo(key *tinkpb.Keyset_Key) (*tinkpb.KeysetInfo_KeyInfo, error) {
	if key == nil {
		return nil, fmt.Errorf("keyset key is nil")
	}

	return &tinkpb.KeysetInfo_KeyInfo{
		TypeUrl:          key.KeyData.TypeUrl,
		Status:           key.Status,
		KeyId:            key.KeyId,
		OutputPrefixType: key.OutputPrefixType,
	}, nil
}
