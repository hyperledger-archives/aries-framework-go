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
	"fmt"

	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/api"
)

// NewECDHESEncrypt returns an ECDHESEncrypt primitive from the given keyset handle.
func NewECDHESEncrypt(h *keyset.Handle) (api.ECDHESEncrypt, error) {
	return NewECDHESEncryptWithKeyManager(h, nil /*keyManager*/)
}

// NewECDHESEncryptWithKeyManager returns an ECDHESEncrypt primitive from the given h keyset handle and
// custom km key manager.
func NewECDHESEncryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (api.ECDHESEncrypt, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_factory: cannot obtain primitive set: %s", err)
	}

	return newEncryptPrimitiveSet(ps), nil
}

// encryptPrimitiveSet is an ECDHESEncrypt implementation that uses the underlying primitive set for encryption.
type encryptPrimitiveSet struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that primitiveSet implements the ECDHESEncrypt interface.
var _ api.ECDHESEncrypt = (*encryptPrimitiveSet)(nil)

func newEncryptPrimitiveSet(ps *primitiveset.PrimitiveSet) *encryptPrimitiveSet {
	ret := new(encryptPrimitiveSet)
	ret.ps = ps

	return ret
}

// Encrypt encrypts the given plaintext with the given additional authenticated data.
// It returns the concatenation of the primary's identifier and the ciphertext.
func (a *encryptPrimitiveSet) Encrypt(pt, ad []byte) ([]byte, error) {
	primary := a.ps.Primary

	var p = (primary.Primitive).(api.ECDHESEncrypt)

	ct, err := p.Encrypt(pt, ad)
	if err != nil {
		return nil, err
	}

	ret := make([]byte, 0, len(primary.Prefix)+len(ct))
	ret = append(ret, primary.Prefix...)
	ret = append(ret, ct...)

	return ret, nil
}
