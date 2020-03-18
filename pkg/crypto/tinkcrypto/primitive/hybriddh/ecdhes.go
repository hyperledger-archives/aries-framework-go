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

// Package hybriddh provides subtle implementations of the HKDF and ECDH-ES primitives.
//
// The functionality of ecdhes Encryption is represented as a pair of
// primitives (interfaces):
//
//  * ECDHESEncrypt for encryption of data
//
//  * ECDHESDecrypt for decryption of data
//
// Implementations of these interfaces are secure against adaptive chosen
// ciphertext attacks. In addition to plaintext the encryption takes an extra
// parameter contextInfo, which usually is public data implicit from the
// context, but should be bound to the resulting ciphertext, i.e. the
// ciphertext allows for checking the integrity of contextInfo (but there are
// no guarantees wrt. the secrecy or authenticity of contextInfo).
//
// Example:
//
//   package main
//
//   import (
//       "github.com/google/tink/go/core/registry"
//       "github.com/google/tink/go/keyset"
//
//       ecdhes "github.com/aries-framework-go/pkg/crypto/tinkcrypto/hybriddh"
//   )
//
//   func main() {
//
//       kh , err := keyset.NewHandle(ecdhes.ECDHESKeyTemplate())
//       if err != nil {
//           //handle error
//       }
//       h := ecdhes.NewECDHESEncrypt(kh)
//
//       ct, err = h.Encrypt([]byte("secret message"), []byte("context info"))
//       if err != nil {
//           // handle error
//       }
//
//       khd , err := keyset.NewHandle( .....); /// get a handle on the decryption key material
//       hd := ecdhes.NewECDHESDecrypt(khd)
//
//       pt, err := hd.Decrypt(ct, []byte("context info"))
//       if err != nil {
//           // handle error
//       }
//   }
package hybriddh

import (
	"fmt"

	"github.com/google/tink/go/core/registry"
)

// nolint: gochecknoinits
func init() {
	err := registry.RegisterKeyManager(newECDHESPrivateKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdhes.init() failed: %v", err))
	}

	err = registry.RegisterKeyManager(newECDHESPublicKeyManager())
	if err != nil {
		panic(fmt.Sprintf("ecdhes.init() failed: %v", err))
	}
}
