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

	"github.com/hyperledger/aries-framework-go/spi/kms"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	bbspb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/bbs_go_proto"
	clpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/cl_go_proto"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
)

const (
	ecdsaSignerTypeURL           = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
	ed25519SignerTypeURL         = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
	bbsSignerKeyTypeURL          = "type.hyperledger.org/hyperledger.aries.crypto.tink.BBSPrivateKey"
	secp256k1SignerTypeURL       = "type.googleapis.com/google.crypto.tink.secp256k1PrivateKey"
	nistpECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
)

//nolint:funlen,gocyclo
func (l *LocalKMS) importECDSAKey(privKey *ecdsa.PrivateKey, kt kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	var params *ecdsapb.EcdsaParams

	err := validECPrivateKey(privKey)
	if err != nil {
		return "", nil, fmt.Errorf("import private EC key failed: %w", err)
	}

	switch kt {
	case kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
		return l.buildAndImportECDSAPrivateKeyAsECDHKW(privKey, kt, opts...)
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
			HashType: commonpb.HashType_SHA384,
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
			HashType: commonpb.HashType_SHA384,
		}
	case kms.ECDSAP521TypeIEEEP1363:
		params = &ecdsapb.EcdsaParams{
			Curve:    commonpb.EllipticCurveType_NIST_P521,
			Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
			HashType: commonpb.HashType_SHA512,
		}
	case kms.ECDSASecp256k1DER:
		return l.importSecp256K1Key(privKey, &secp256k1pb.Secp256K1Params{
			HashType: commonpb.HashType_SHA256,
			Curve:    secp256k1pb.BitcoinCurveType_SECP256K1,
			Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER,
		})
	case kms.ECDSASecp256k1IEEEP1363:
		return l.importSecp256K1Key(privKey, &secp256k1pb.Secp256K1Params{
			HashType: commonpb.HashType_SHA256,
			Curve:    secp256k1pb.BitcoinCurveType_SECP256K1,
			Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363,
		})
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

func (l *LocalKMS) importSecp256K1Key(privKey *ecdsa.PrivateKey, params *secp256k1pb.Secp256K1Params,
	opts ...kms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	mKeyValue, err := getMarshalledECDSASecp256K1PrivateKey(privKey, params)
	if err != nil {
		return "", nil, fmt.Errorf("import private EC secp256k1 key failed: %w", err)
	}

	ks := newKeySet(secp256k1SignerTypeURL, mKeyValue, tinkpb.KeyData_ASYMMETRIC_PRIVATE)

	return l.importKeySet(ks, opts...)
}

func (l *LocalKMS) buildAndImportECDSAPrivateKeyAsECDHKW(privKey *ecdsa.PrivateKey, kt kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	var keyTemplate *tinkpb.KeyTemplate

	switch kt {
	case kms.NISTP256ECDHKWType:
		keyTemplate = ecdh.NISTP256ECDHKWKeyTemplate()
	case kms.NISTP384ECDHKWType:
		keyTemplate = ecdh.NISTP384ECDHKWKeyTemplate()
	case kms.NISTP521ECDHKWType:
		keyTemplate = ecdh.NISTP521ECDHKWKeyTemplate()
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)

	err := proto.Unmarshal(keyTemplate.Value, keyFormat)
	if err != nil {
		return "", nil, fmt.Errorf("invalid key format")
	}

	priv := &ecdhpb.EcdhAeadPrivateKey{
		Version:  0,
		KeyValue: privKey.D.Bytes(),
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: 0,
			Params:  keyFormat.Params,
			X:       privKey.PublicKey.X.Bytes(),
			Y:       privKey.PublicKey.Y.Bytes(),
		},
	}

	privBytes, err := proto.Marshal(priv)
	if err != nil {
		return "", nil, fmt.Errorf("marshal protobuf: %w", err)
	}

	ks := newKeySet(nistpECDHKWPrivateKeyTypeURL, privBytes, tinkpb.KeyData_ASYMMETRIC_PRIVATE)

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

func getMarshalledECDSASecp256K1PrivateKey(privKey *ecdsa.PrivateKey,
	params *secp256k1pb.Secp256K1Params) ([]byte, error) {
	pubKeyProto := newProtoSecp256K1PublicKey(&privKey.PublicKey, params)
	return proto.Marshal(newProtoECDSASecp256K1PrivateKey(pubKeyProto, privKey.D.Bytes()))
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

func (l *LocalKMS) importBBSKey(privKey *bbs12381g2pub.PrivateKey, kt kms.KeyType,
	opts ...kms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	if privKey == nil {
		return "", nil, fmt.Errorf("import private BBS+ key failed: private key is nil")
	}

	if kt != kms.BLS12381G2Type {
		return "", nil, fmt.Errorf("import private BBS+ key failed: invalid key type")
	}

	privKeyProto, err := newProtoBBSPrivateKey(privKey, kt)
	if err != nil {
		return "", nil, fmt.Errorf("import private BBS+ key failed: %w", err)
	}

	mKeyValue, err := proto.Marshal(privKeyProto)
	if err != nil {
		return "", nil, fmt.Errorf("import private BBS+ key failed: %w", err)
	}

	ks := newKeySet(bbsSignerKeyTypeURL, mKeyValue, tinkpb.KeyData_ASYMMETRIC_PRIVATE)

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

// newProtoECDSASecp256K1PrivateKey creates a Secp256K1PrivateKey with the specified parameters.
func newProtoECDSASecp256K1PrivateKey(publicKey *secp256k1pb.Secp256K1PublicKey,
	keyValue []byte) *secp256k1pb.Secp256K1PrivateKey {
	return &secp256k1pb.Secp256K1PrivateKey{
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

func newProtoBBSPrivateKey(privateKey *bbs12381g2pub.PrivateKey, kt kms.KeyType) (*bbspb.BBSPrivateKey, error) {
	publicKey := privateKey.PublicKey()

	pubKeyBytes, err := publicKey.Marshal()
	if err != nil {
		return nil, err
	}

	publicProto := &bbspb.BBSPublicKey{
		Version:  0,
		Params:   buidBBSParams(kt),
		KeyValue: pubKeyBytes,
	}

	privKeyBytes, err := privateKey.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbspb.BBSPrivateKey{
		Version:   0,
		PublicKey: publicProto,
		KeyValue:  privKeyBytes,
	}, nil
}

func buidBBSParams(kt kms.KeyType) *bbspb.BBSParams {
	if kt == kms.BLS12381G2Type {
		return &bbspb.BBSParams{
			HashType: commonpb.HashType_SHA256,
			Curve:    bbspb.BBSCurveType_BLS12_381,
			Group:    bbspb.GroupField_G2,
		}
	}

	return nil
}

func buidCLCredDefParams(kt kms.KeyType, opts ...kms.KeyOpts) *clpb.CLCredDefParams {
	if kt == kms.CLCredDefType {
		keyOpts := kms.NewKeyOpt()

		for _, opt := range opts {
			opt(keyOpts)
		}

		return &clpb.CLCredDefParams{
			Attrs: keyOpts.Attrs(),
		}
	}

	return nil
}

func (l *LocalKMS) writeImportedKey(ks *tinkpb.Keyset, opts ...kms.PrivateKeyOpts) (string, error) {
	serializedKeyset, err := proto.Marshal(ks)
	if err != nil {
		return "", fmt.Errorf("invalid keyset data")
	}

	encrypted, err := l.primaryKeyEnvAEAD.Encrypt(serializedKeyset, []byte{})
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
