/*
Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hybriddh

import (
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/proto/common_go_proto"
	eahpb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/subtle"
)

const (
	ecdhesPrivateKeyVersion = 0
	ecdhesPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.ecdhesPrivateKey"
)

// common errors
var errInvalidECDHESPrivateKey = fmt.Errorf("ecdhes_private_key_manager: invalid key")
var errInvalidECDHESPrivateKeyFormat = fmt.Errorf("ecdhes_private_key_manager: invalid key format")

// ecdhesPrivateKeyManager is an implementation of PrivateKeyManager interface.
// It generates new ECDHESPrivateKey keys and produces new instances of ECDHESPrivateKey subtle.
type ecdhesPrivateKeyManager struct{}

// Assert that ecdhesPrivateKeyManager implements the PrivateKeyManager interface.
var _ registry.PrivateKeyManager = (*ecdhesPrivateKeyManager)(nil)

// newECDHESPrivateKeyManager creates a new aesGcmKeyManager.
func newECDHESPrivateKeyManager() *ecdhesPrivateKeyManager {
	return new(ecdhesPrivateKeyManager)
}

// Primitive creates an ECDHESPrivateKey subtle for the given serialized ECDHESPrivateKey proto.
func (km *ecdhesPrivateKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHESPrivateKey
	}

	key := new(eahpb.EciesAeadHkdfPrivateKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	curve, err := subtle.GetCurve(key.PublicKey.Params.KemParams.CurveType.String())
	if err != nil {
		return nil, err
	}

	pvt := subtle.GetECPrivateKey(curve, key.KeyValue)

	rDem, err := newRegisterECDHESDemHelper(key.PublicKey.Params.DemParams.AeadDem)
	if err != nil {
		return nil, err
	}

	salt := key.PublicKey.Params.KemParams.HkdfSalt
	hash := key.PublicKey.Params.KemParams.HkdfHashType.String()
	ptFormat := key.PublicKey.Params.EcPointFormat.String()

	return subtle.NewECDHESDecrypt(pvt, salt, hash, ptFormat, rDem)
}

// NewKey creates a new key according to specification the given serialized ECDHESAESGCMPrivateKeyFormat.
func (km *ecdhesPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDHESPrivateKeyFormat
	}

	keyFormat := new(eahpb.EciesAeadHkdfKeyFormat)

	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidECDHESPrivateKeyFormat
	}

	err = km.validateKeyFormat(keyFormat)
	if err != nil {
		return nil, errInvalidECDHESPrivateKeyFormat
	}

	curve, err := subtle.GetCurve(keyFormat.Params.KemParams.CurveType.String())
	if err != nil {
		return nil, err
	}

	pvt, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, err
	}

	return &eahpb.EciesAeadHkdfPrivateKey{
		Version:  ecdhesPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &eahpb.EciesAeadHkdfPublicKey{
			Version: ecdhesPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

// NewKeyData creates a new KeyData according to specification in the given serialized ECDHESPrivateKeyFormat.
// It should be used solely by the key management API.
func (km *ecdhesPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhesPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *ecdhesPrivateKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(eahpb.EciesAeadHkdfPrivateKey)

	err := proto.Unmarshal(serializedPrivKey, privKey)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDHESPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         ecdhesPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhesPrivateKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhesPrivateKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhesPrivateKeyManager) TypeURL() string {
	return ecdhesPrivateKeyTypeURL
}

// validateKey validates the given ECDHESPrivateKey.
func (km *ecdhesPrivateKeyManager) validateKey(key *eahpb.EciesAeadHkdfPrivateKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdhesPrivateKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdhes_aesgcm_private_key_manager: invalid key: %s", err)
	}

	return checkECDHESParams(key.PublicKey.Params)
}

// validateKeyFormat validates the given ECDSAKeyFormat.
func (km *ecdhesPrivateKeyManager) validateKeyFormat(format *eahpb.EciesAeadHkdfKeyFormat) error {
	return checkECDHESParams(format.Params)
}

func checkECDHESParams(params *eahpb.EciesAeadHkdfParams) error {
	_, err := subtle.GetCurve(params.KemParams.CurveType.String())
	if err != nil {
		return err
	}

	if params.KemParams.HkdfHashType.String() == commonpb.HashType_UNKNOWN_HASH.String() {
		return errors.New("hash unsupported for HMAC")
	}

	if params.EcPointFormat.String() == commonpb.EcPointFormat_UNKNOWN_FORMAT.String() {
		return errors.New("unknown EC point format")
	}

	km, err := registry.GetKeyManager(params.DemParams.AeadDem.TypeUrl)
	if err != nil {
		return err
	}

	_, err = km.NewKeyData(params.DemParams.AeadDem.Value)
	if err != nil {
		return err
	}

	return nil
}
