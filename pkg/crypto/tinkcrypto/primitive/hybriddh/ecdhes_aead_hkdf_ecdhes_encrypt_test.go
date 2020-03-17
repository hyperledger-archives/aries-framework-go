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
	"bytes"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/subtle/random"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/subtle"
)

func basicMultipleEncrypts(t *testing.T, crv string, k *tinkpb.KeyTemplate) {
	t.Helper()

	curve, err := subtle.GetCurve(crv)
	require.NoError(t, err)
	require.NotEmpty(t, curve)

	pvt, err := subtle.GenerateECDHKeyPair(curve)
	require.NoError(t, err, "error generating ECDH key pair")

	salt := []byte("some salt")
	pt := random.GetRandomBytes(20)
	context := []byte("context info")

	rDem, err := newRegisterECDHESDemHelper(k)
	require.NoError(t, err, "error generating a DEM helper")

	e, err := subtle.NewECDHESEncrypt(&pvt.PublicKey, salt, "SHA256", "UNCOMPRESSED", rDem)
	require.NoError(t, err, "error generating an encryption construct")

	d, err := subtle.NewECDHESDecrypt(pvt, salt, "SHA256", "UNCOMPRESSED", rDem)
	require.NoError(t, err, "error generating an decryption construct")

	var cl [][]byte

	for i := 0; i < 8; i++ {
		ct, err := e.Encrypt(pt, context)
		require.NoError(t, err, "encryption error")

		for _, c := range cl {
			if bytes.Equal(ct, c) {
				t.Fatalf("encryption is not randomized")
			}
		}

		cl = append(cl, ct)
		dt, err := d.Decrypt(ct, context)
		require.NoError(t, err, "decryption error")

		if !bytes.Equal(dt, pt) {
			t.Fatalf("decryption not inverse of encryption")
		}
	}

	require.Equal(t, 8, len(cl), "randomized encryption check failed")
}

func TestECAES256GCMEncrypt(t *testing.T) {
	basicMultipleEncrypts(t, "NIST_P256", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES256GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES256GCMKeyTemplate())

	basicMultipleEncrypts(t, "NIST_P256", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P384", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P521", aead.AES128GCMKeyTemplate())
	basicMultipleEncrypts(t, "NIST_P224", aead.AES128GCMKeyTemplate())
}
