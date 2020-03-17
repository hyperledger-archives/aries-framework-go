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
	"math/big"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	eahpb "github.com/google/tink/proto/ecies_aead_hkdf_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/subtle"
)

const (
	ecdhesPublicKeyVersion = 0

	ecdhesPublicKeyTypeURL = "type.googleapis.com/google.crypto.tink.ecdhesPublicKey"
)

// common errors
var errInvalidECDHESPublicKey = fmt.Errorf("ecdhes_public_key_manager: invalid key")

// ecdhesPublicKeyManager is an implementation of KeyManager interface.
// It generates new ECDHESPublicKey keys and produces new instances of ECDHESPublicKey subtle.
type ecdhesPublicKeyManager struct{}

// Assert that ecdhesPublicKeyManager implements the KeyManager interface.
var _ registry.KeyManager = (*ecdhesPublicKeyManager)(nil)

// newECDHESPublicKeyManager creates a new aesGcmKeyManager.
func newECDHESPublicKeyManager() *ecdhesPublicKeyManager {
	return new(ecdhesPublicKeyManager)
}

// Primitive creates an ECDHESPublicKey subtle for the given serialized ECDHESPublicKey proto.
func (km *ecdhesPublicKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDHESPublicKey
	}

	key := new(eahpb.EciesAeadHkdfPublicKey)

	err := proto.Unmarshal(serializedKey, key)
	if err != nil {
		return nil, errInvalidECDHESPublicKey
	}

	err = km.validateKey(key)
	if err != nil {
		return nil, errInvalidECDHESPublicKey
	}

	curve, err := subtle.GetCurve(key.Params.KemParams.CurveType.String())
	if err != nil {
		return nil, err
	}

	pub := subtle.ECPublicKey{
		Curve: curve,
		Point: subtle.ECPoint{
			X: new(big.Int).SetBytes(key.X),
			Y: new(big.Int).SetBytes(key.Y),
		},
	}

	rDem, err := newRegisterECDHESDemHelper(key.Params.DemParams.AeadDem)
	if err != nil {
		return nil, err
	}

	salt := key.Params.KemParams.HkdfSalt
	hash := key.Params.KemParams.HkdfHashType.String()
	ptFormat := key.Params.EcPointFormat.String()

	return subtle.NewECDHESEncrypt(&pub, salt, hash, ptFormat, rDem)
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdhesPublicKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdhesPublicKeyTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdhesPublicKeyManager) TypeURL() string {
	return ecdhesPublicKeyTypeURL
}

// validateKey validates the given ECDHESPublicKey.
func (km *ecdhesPublicKeyManager) validateKey(key *eahpb.EciesAeadHkdfPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, ecdhesPublicKeyVersion)
	if err != nil {
		return fmt.Errorf("ecdhes_public_key_manager: invalid key: %s", err)
	}

	return checkECDHESParams(key.Params)
}

// NewKey is not implemented for public key manager.
func (km *ecdhesPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("public key manager does not implement NewKey")
}

// NewKeyData is not implemented for public key manager.
func (km *ecdhesPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("public key manager does not implement NewKeyData")
}
