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

package subtle

import "github.com/google/tink/go/tink"

// ECDHESDEMHelper a helper for DEM (data encapsulation mechanism) of ECDH-ES (AEAD-HKDF).
type ECDHESDEMHelper interface {

	// GetSymmetricKeySize gives the size of the DEM-key in bytes
	GetSymmetricKeySize() uint32

	// GetAEAD returns the newly created AEAD primitive.
	GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error)
}
