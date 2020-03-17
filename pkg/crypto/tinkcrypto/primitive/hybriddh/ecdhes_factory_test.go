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

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	commonpb "github.com/google/tink/proto/common_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
	"github.com/stretchr/testify/require"
)

func TestECDHESFactoryTest(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P256
	ht := commonpb.HashType_SHA256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryDek := aead.AES128GCMKeyTemplate()
	rawDek := aead.AES256GCMKeyTemplate()
	primarySalt := []byte("some salt")
	rawSalt := []byte("other salt")

	primaryPrivProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, primaryPtFmt, primaryDek, primarySalt)
	require.NoError(t, err)

	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdhesPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, ht, rawPtFmt, rawDek, rawSalt)
	require.NoError(t, err)

	sRawPriv, err := proto.Marshal(rawPrivProto)
	require.NoError(t, err)

	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdhesPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)

	khPub, err := khPriv.Public()
	if err != nil {
		t.Error(err)
	}

	e, err := NewECDHESEncrypt(khPub)
	require.NoError(t, err)

	d, err := NewECDHESDecrypt(khPriv)
	require.NoError(t, err)

	for i := 0; i < 1000; i++ {
		pt := random.GetRandomBytes(20)
		ci := random.GetRandomBytes(20)
		ct, err := e.Encrypt(pt, ci)
		require.NoError(t, err)

		gotpt, err := d.Decrypt(ct, ci)
		require.NoError(t, err)

		if !bytes.Equal(pt, gotpt) {
			t.Error("expected pt:", pt, " not equal to decrypted pt:", gotpt)
		}
	}
}
