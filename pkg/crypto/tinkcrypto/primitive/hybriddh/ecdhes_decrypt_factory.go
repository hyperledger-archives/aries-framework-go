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

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/api"
)

// NewECDHESDecrypt returns an ECDHESDecrypt primitive from the given keyset handle.
func NewECDHESDecrypt(h *keyset.Handle) (api.ECDHESDecrypt, error) {
	return NewECDHESDecryptWithKeyManager(h, nil /*keyManager*/)
}

// NewECDHESDecryptWithKeyManager returns an ECDHESDecrypt primitive from the given keyset handle and custom key
// manager.
func NewECDHESDecryptWithKeyManager(h *keyset.Handle, km registry.KeyManager) (api.ECDHESDecrypt, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("ecdhes_factory: cannot obtain primitive set: %s", err)
	}

	return newDecryptPrimitiveSet(ps), nil
}

// decryptPrimitiveSet is an ECDHESDecrypt implementation that uses the underlying primitive set for
// decryption.
type decryptPrimitiveSet struct {
	ps *primitiveset.PrimitiveSet
}

// Asserts that primitiveSet implements the ECDHESDecrypt interface.
var _ api.ECDHESDecrypt = (*decryptPrimitiveSet)(nil)

func newDecryptPrimitiveSet(ps *primitiveset.PrimitiveSet) *decryptPrimitiveSet {
	ret := new(decryptPrimitiveSet)
	ret.ps = ps

	return ret
}

// Decrypt decrypts the given ciphertext and authenticates it with the given
// additional authenticated data. It returns the corresponding plaintext if the
// ciphertext is authenticated.
func (a *decryptPrimitiveSet) Decrypt(ct, ad []byte) ([]byte, error) {
	// try non-raw keys
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(ct) > prefixSize {
		prefix := ct[:prefixSize]
		ctNoPrefix := ct[prefixSize:]

		entries, err := a.ps.EntriesForPrefix(string(prefix))
		if err == nil {
			for i := 0; i < len(entries); i++ {
				var p = (entries[i].Primitive).(api.ECDHESDecrypt)

				pt, err := p.Decrypt(ctNoPrefix, ad)
				if err == nil {
					return pt, nil
				}
			}
		}
	}

	// try raw keys
	entries, err := a.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var p = (entries[i].Primitive).(api.ECDHESDecrypt)

			pt, err := p.Decrypt(ct, ad)
			if err == nil {
				return pt, nil
			}
		}
	}
	// nothing worked
	return nil, fmt.Errorf("ecdhes_factory: decryption failed")
}
