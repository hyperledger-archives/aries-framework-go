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

import (
	"errors"

	"github.com/google/tink/go/tink"
)

// ECDHESDecrypt is an instance of ECDH-ES decryption with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
type ECDHESDecrypt struct {
	privateKey   *ECPrivateKey
	hkdfSalt     []byte
	hkdfHMACAlgo string
	pointFormat  string
	demHelper    ECDHESDEMHelper
}

var _ tink.HybridDecrypt = (*ECDHESDecrypt)(nil)

// NewECDHESDecrypt returns ECDH-ES decryption construct with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
func NewECDHESDecrypt(pvt *ECPrivateKey, hkdfSalt []byte, hkdfHMACAlgo, ptFormat string,
	demHelper ECDHESDEMHelper) (*ECDHESDecrypt, error) {
	return &ECDHESDecrypt{
		privateKey:   pvt,
		hkdfSalt:     hkdfSalt,
		hkdfHMACAlgo: hkdfHMACAlgo,
		pointFormat:  ptFormat,
		demHelper:    demHelper,
	}, nil
}

// Decrypt is used to decrypt using ECDH-ES with a HKDF-KEM and AEAD-DEM mechanisms.
func (e *ECDHESDecrypt) Decrypt(ciphertext, contextInfo []byte) ([]byte, error) {
	curve := e.privateKey.PublicKey.Curve

	headerSize, err := encodingSizeInBytes(curve, e.pointFormat)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < headerSize {
		return nil, errors.New("ciphertext too short")
	}

	var kemBytes = make([]byte, headerSize)

	var ct = make([]byte, len(ciphertext)-headerSize)

	copy(kemBytes, ciphertext[:headerSize])
	copy(ct, ciphertext[headerSize:])

	rKem := &ECDHESRecipientKem{
		recipientPrivateKey: e.privateKey,
	}

	symmetricKey, err := rKem.decapsulate(kemBytes, e.hkdfHMACAlgo, e.hkdfSalt, contextInfo,
		e.demHelper.GetSymmetricKeySize(), e.pointFormat)
	if err != nil {
		return nil, err
	}

	aead, err := e.demHelper.GetAEAD(symmetricKey)
	if err != nil {
		return nil, err
	}

	return aead.Decrypt(ct, []byte{})
}
