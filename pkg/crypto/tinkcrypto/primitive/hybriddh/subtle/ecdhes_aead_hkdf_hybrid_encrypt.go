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
	"bytes"

	"github.com/google/tink/go/tink"
)

// ECDHESEncrypt is an instance of ECDH-ES encryption with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
type ECDHESEncrypt struct {
	publicKey    *ECPublicKey
	hkdfSalt     []byte
	hkdfHMACAlgo string
	pointFormat  string
	demHelper    ECDHESDEMHelper
}

var _ tink.HybridEncrypt = (*ECDHESEncrypt)(nil)

// NewECDHESEncrypt returns ECDH-ES encryption construct with HKDF-KEM (key encapsulation mechanism)
// and AEAD-DEM (data encapsulation mechanism).
func NewECDHESEncrypt(pub *ECPublicKey, hkdfSalt []byte, hkdfHMACAlgo, ptFormat string,
	demHelper ECDHESDEMHelper) (*ECDHESEncrypt, error) {
	c, err := GetCurve(pub.Curve.Params().Name)
	if err != nil {
		return nil, err
	}

	return &ECDHESEncrypt{
		publicKey: &ECPublicKey{
			Curve: c,
			Point: pub.Point,
		},
		hkdfSalt:     hkdfSalt,
		hkdfHMACAlgo: hkdfHMACAlgo,
		pointFormat:  ptFormat,
		demHelper:    demHelper,
	}, nil
}

// Encrypt is used to encrypt using ECDH-ES with a HKDF-KEM and AEAD-DEM mechanisms.
func (e *ECDHESEncrypt) Encrypt(plaintext, contextInfo []byte) ([]byte, error) {
	var b bytes.Buffer

	sKem := &ECDHESSenderKem{
		recipientPublicKey: e.publicKey,
	}

	kemKey, err := sKem.encapsulate(e.hkdfHMACAlgo, e.hkdfSalt, contextInfo,
		e.demHelper.GetSymmetricKeySize(), e.pointFormat)
	if err != nil {
		return nil, err
	}

	aead, err := e.demHelper.GetAEAD(kemKey.SymmetricKey)
	if err != nil {
		return nil, err
	}

	ct, err := aead.Encrypt(plaintext, []byte{})
	if err != nil {
		return nil, err
	}

	_, err = b.Write(kemKey.Kem)
	if err != nil {
		return nil, err
	}

	_, err = b.Write(ct)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
