/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	subtleSignature "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
)

const (
	secp256k1SignerKeyVersion = 0
	secp256k1SignerTypeURL    = "type.googleapis.com/google.crypto.tink.secp256k1PrivateKey"
)

// common errors.
var (
	errInvalidSECP256K1SignKey       = errors.New("secp256k1_signer_key_manager: invalid key")
	errInvalidSECP256K1SignKeyFormat = errors.New("secp256k1_signer_key_manager: invalid key format")
)

// secp256k1SignerKeyManager is an implementation of KeyManager interface.
// It generates new Secp256K1PrivateKeys and produces new instances of ECDSASign subtle.
type secp256k1SignerKeyManager struct{}

// newSecp256K2SignerKeyManager creates a new secp256k1SignerKeyManager.
func newSecp256K2SignerKeyManager() *secp256k1SignerKeyManager {
	return new(secp256k1SignerKeyManager)
}

// Primitive creates an ECDSASign subtle for the given serialized ECDSAPrivateKey proto.
func (km *secp256k1SignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidSECP256K1SignKey
	}

	key := new(secp256k1pb.Secp256K1PrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidSECP256K1SignKey
	}

	if err := km.validateKey(key); err != nil {
		return nil, err
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.PublicKey.Params)

	ret, err := subtleSignature.NewSecp256K1Signer(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: %w", err)
	}

	return ret, nil
}

// NewKey creates a new ECDSAPrivateKey according to specification the given serialized ECDSAKeyFormat.
func (km *secp256k1SignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidSECP256K1SignKeyFormat
	}

	keyFormat := new(secp256k1pb.Secp256K1KeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: invalid proto: %w", err)
	}

	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: invalid key format: %w", err)
	}

	// generate key
	params := keyFormat.Params

	tmpKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: cannot generate ECDSA key: %w", err)
	}

	keyValue := tmpKey.D.Bytes()
	pub := newSecp256K1PublicKey(secp256k1SignerKeyVersion, params, tmpKey.X.Bytes(), tmpKey.Y.Bytes())
	priv := newSecp256K1PrivateKey(secp256k1SignerKeyVersion, pub, keyValue)

	return priv, nil
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized ECDSAKeyFormat. It should be used solely by the key management API.
func (km *secp256k1SignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidSECP256K1SignKeyFormat
	}

	return &tinkpb.KeyData{
		TypeUrl:         secp256k1SignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *secp256k1SignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(secp256k1pb.Secp256K1PrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidSECP256K1SignKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidSECP256K1SignKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         secp256k1VerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *secp256k1SignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == secp256k1SignerTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *secp256k1SignerKeyManager) TypeURL() string {
	return secp256k1SignerTypeURL
}

// validateKey validates the given ECDSAPrivateKey.
func (km *secp256k1SignerKeyManager) validateKey(key *secp256k1pb.Secp256K1PrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, secp256k1SignerKeyVersion); err != nil {
		return fmt.Errorf("secp256k1_signer_key_manager: invalid key: %w", err)
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.PublicKey.Params)

	return ValidateSecp256K1Params(hash, curve, encoding)
}

// validateKeyFormat validates the given ECDSAKeyFormat.
func (km *secp256k1SignerKeyManager) validateKeyFormat(format *secp256k1pb.Secp256K1KeyFormat) error {
	hash, curve, encoding := getSecp256K1ParamNames(format.Params)
	return ValidateSecp256K1Params(hash, curve, encoding)
}

// ValidateSecp256K1Params validates ECDSA parameters.
// The hash's strength must not be weaker than the curve's strength.
// DER and IEEE_P1363 encodings are supported.
func ValidateSecp256K1Params(hashAlg, curve, encoding string) error {
	switch encoding {
	case "Bitcoin_DER":
	case "Bitcoin_IEEE_P1363":
	default:
		return errors.New("secp256k1: unsupported encoding")
	}

	switch curve {
	case "SECP256K1":
		if hashAlg != "SHA256" {
			return errors.New("invalid hash type for secp256k1 curve, expect SHA-256")
		}
	default:
		return fmt.Errorf("unsupported curve: %s", curve)
	}

	return nil
}

// getSecp256K1ParamNames returns the string representations of each parameter in
// the given secp256k1Params.
func getSecp256K1ParamNames(params *secp256k1pb.Secp256K1Params) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.HashType)]
	curveName := secp256k1pb.BitcoinCurveType_name[int32(params.Curve)]
	encodingName := secp256k1pb.Secp256K1SignatureEncoding_name[int32(params.Encoding)]

	return hashName, curveName, encodingName
}

// newSecp256K1PublicKey creates a Secp256K1PublicKey with the specified parameters.
func newSecp256K1PublicKey(version uint32,
	params *secp256k1pb.Secp256K1Params,
	x []byte, y []byte) *secp256k1pb.Secp256K1PublicKey {
	return &secp256k1pb.Secp256K1PublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}

// newSecp256K1PrivateKey creates a Secp256K1PrivateKey with the specified parameters.
func newSecp256K1PrivateKey(version uint32,
	publicKey *secp256k1pb.Secp256K1PublicKey,
	keyValue []byte) *secp256k1pb.Secp256K1PrivateKey {
	return &secp256k1pb.Secp256K1PrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}
