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
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
	gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/subtle"
)

const (
	// nolint:gochecknoglobals
	aesGCMTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmKey"
)

// registerECDHESDemHelper registers a DEM helper.
type registerECDHESDemHelper struct {
	demKeyURL        string
	keyData          []byte
	symmetricKeySize uint32
	aesCTRSize       uint32
}

var _ subtle.ECDHESDEMHelper = (*registerECDHESDemHelper)(nil)

// newRegisterECDHESDemHelper initializes and returns a RegisterECDHESDemHelper
func newRegisterECDHESDemHelper(k *tinkpb.KeyTemplate) (*registerECDHESDemHelper, error) {
	var keyLen, a uint32

	var skf []byte

	var err error

	u := k.TypeUrl

	if strings.Compare(u, aesGCMTypeURL) == 0 {
		gcmKeyFormat := new(gcmpb.AesGcmKeyFormat)

		err = proto.Unmarshal(k.Value, gcmKeyFormat)
		if err != nil {
			return nil, err
		}

		keyLen = gcmKeyFormat.KeySize
		a = 0

		skf, err = proto.Marshal(gcmKeyFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key format, error :%v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported AEAD DEM key type: %s", u)
	}

	km, err := registry.GetKeyManager(k.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KeyManager, error: %v", err)
	}

	key, err := km.NewKey(skf)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key, error: %v", err)
	}

	sk, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key, error: %v", err)
	}

	return &registerECDHESDemHelper{
		demKeyURL:        u,
		keyData:          sk,
		symmetricKeySize: keyLen,
		aesCTRSize:       a,
	}, nil
}

// GetSymmetricKeySize returns the symmetric key size
func (r *registerECDHESDemHelper) GetSymmetricKeySize() uint32 {
	return r.symmetricKeySize
}

// GetAEAD returns the AEAD primitive from the DEM
func (r *registerECDHESDemHelper) GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error) {
	var sk []byte

	if uint32(len(symmetricKeyValue)) != r.GetSymmetricKeySize() {
		return nil, errors.New("symmetric key has incorrect length")
	}

	switch r.demKeyURL {
	case aesGCMTypeURL:
		gcmKey := new(gcmpb.AesGcmKey)

		err := proto.Unmarshal(r.keyData, gcmKey)
		if err != nil {
			return nil, err
		}

		gcmKey.KeyValue = symmetricKeyValue

		sk, err = proto.Marshal(gcmKey)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize key, error: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported AEAD DEM key type: %s", r.demKeyURL)
	}

	p, err := registry.Primitive(r.demKeyURL, sk)
	if err != nil {
		return nil, err
	}

	g, ok := p.(tink.AEAD)
	if !ok {
		return nil, fmt.Errorf("key is not of type AEAD")
	}

	return g, nil
}
