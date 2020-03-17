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
	"github.com/stretchr/testify/require"

	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testutil"
	tinkpb "github.com/google/tink/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/hybriddh/subtle"
)

func modifyDecrypt(t *testing.T, c string, k *tinkpb.KeyTemplate) {
	t.Helper()

	curve, err := subtle.GetCurve(c)
	require.NoError(t, err)
	require.NotEmpty(t, curve)

	pvt, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		t.Fatalf("error generating ECDH key pair: %s", err)
	}

	salt := random.GetRandomBytes(8)
	pt := random.GetRandomBytes(4)
	context := random.GetRandomBytes(4)

	rDem, err := newRegisterECDHESDemHelper(k)
	require.NoError(t, err, "error generating a DEM helper")

	e, err := subtle.NewECDHESEncrypt(&pvt.PublicKey, salt, "SHA256", "UNCOMPRESSED", rDem)
	require.NoError(t, err, "error generating an encryption construct")

	d, err := subtle.NewECDHESDecrypt(pvt, salt, "SHA256", "UNCOMPRESSED", rDem)
	require.NoError(t, err, "error generating an decryption construct")

	ct, err := e.Encrypt(pt, context)
	require.NoError(t, err, "encryption error")

	dt, err := d.Decrypt(ct, context)
	require.NoError(t, err, "decryption error")

	if !bytes.Equal(dt, pt) {
		t.Fatalf("decryption not inverse of encryption")
	}

	for _, g := range testutil.GenerateMutations(ct) {
		_, err = d.Decrypt(g, context)
		require.Error(t, err, "invalid cipher text should throw exception")
	}

	for _, g := range testutil.GenerateMutations(context) {
		_, err = d.Decrypt(ct, g)
		require.Error(t, err, "invalid context should throw exception")
	}

	mSalt := make([]byte, len(salt))

	for i := 0; i < len(salt); i++ {
		for j := 0; j < 8; j++ {
			copy(mSalt, salt)
			mSalt[i] ^= (1 << uint8(j))

			d, err = subtle.NewECDHESDecrypt(pvt, mSalt, "SHA256", "UNCOMPRESSED", rDem)
			require.NoError(t, err, "subtle.NewECDHESDecrypt")

			_, err = d.Decrypt(ct, context)
			require.Error(t, err, "invalid salt should throw exception")
		}
	}
}

func TestECDHESDecrypt(t *testing.T) {
	modifyDecrypt(t, "NIST_P256", aead.AES256GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P384", aead.AES256GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P521", aead.AES256GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P224", aead.AES256GCMKeyTemplate())

	modifyDecrypt(t, "NIST_P256", aead.AES128GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P384", aead.AES128GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P521", aead.AES128GCMKeyTemplate())
	modifyDecrypt(t, "NIST_P224", aead.AES128GCMKeyTemplate())
}
