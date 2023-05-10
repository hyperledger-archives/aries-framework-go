/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

func Test_ExtractPrivKey(t *testing.T) {
	_, err := extractPrivKey(nil)
	require.EqualError(t, err, "extractPrivKey: kh is nil")

	badKey, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	_, err = extractPrivKey(badKey)
	require.EqualError(t, err, "extractPrivKey: can't extract unsupported private key 'type.googleapis.com/"+
		"google.crypto.tink.AesGcmKey'")

	require.PanicsWithValue(t, "keyset.Handle: keyset must be non nil", func() {
		_, _ = extractPrivKey(&keyset.Handle{}) //nolint:errcheck // Expected to panic
	})

	badPrivateKeyProto := generateECDHAEADPrivateKey(t, commonpb.EllipticCurveType_CURVE25519, // <-- invalid EC curve
		ecdhpb.KeyType_EC, aead.AES128GCMKeyTemplate(), random.GetRandomBytes(32))

	badPrivMarshalledProto, err := proto.Marshal(badPrivateKeyProto)
	require.NoError(t, err)

	badPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistPECDHKWPrivateKeyTypeURL, badPrivMarshalledProto, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 15, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{badPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)

	_, err = extractPrivKey(khPriv)
	require.EqualError(t, err, "extractPrivKey: invalid key: unsupported curve")

	badPrivateKeyProto = generateECDHAEADPrivateKey(t, commonpb.EllipticCurveType_NIST_P256, // <-- invalid OKP curve
		ecdhpb.KeyType_OKP, aead.XChaCha20Poly1305KeyTemplate(),
		random.GetRandomBytes(32))

	badPrivMarshalledProto, err = proto.Marshal(badPrivateKeyProto)
	require.NoError(t, err)

	badPrivKey = testutil.NewKey(
		testutil.NewKeyData(x25519ECDHKWPrivateKeyTypeURL, badPrivMarshalledProto, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 15, tinkpb.OutputPrefixType_RAW)

	privKeys = []*tinkpb.Keyset_Key{badPrivKey}
	privKeyset = testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err = testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)

	_, err = extractPrivKey(khPriv)
	require.EqualError(t, err, "extractPrivKey: invalid key curve")
}

// generateECDHAEADPrivateKey generates a new EC key pair and returns the private key proto.
func generateECDHAEADPrivateKey(t *testing.T, c commonpb.EllipticCurveType, kt ecdhpb.KeyType, encT *tinkpb.KeyTemplate,
	cek []byte) *ecdhpb.EcdhAeadPrivateKey {
	t.Helper()

	ptfmt := commonpb.EcPointFormat_UNCOMPRESSED

	if ecdhpb.KeyType_OKP.String() == kt.String() {
		return buildXChachaKey(t, ptfmt, encT, c, cek)
	}

	// don't set curve from c because we want the wrong c value to be set in the key
	// generate a P-256 key by default
	// curve, err := hybrid.GetCurve(c.String())
	// require.NoError(t, err)

	pvt, err := hybrid.GenerateECDHKeyPair(elliptic.P256())
	require.NoError(t, err)

	pubK := ecdhAEADPublicKey(t, c, ptfmt, kt, encT, pvt.PublicKey.Point.X.Bytes(), pvt.PublicKey.Point.Y.Bytes(), cek)

	return ecdhesAEADPrivateKey(t, pubK, pvt.D.Bytes())
}

func buildXChachaKey(t *testing.T, ptfmt commonpb.EcPointFormat, encT *tinkpb.KeyTemplate, c commonpb.EllipticCurveType,
	cek []byte) *ecdhpb.EcdhAeadPrivateKey {
	pub, pvt, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
	require.NoError(t, err)

	x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
	require.NoError(t, err)

	params := &ecdhpb.EcdhAeadParams{
		KwParams: &ecdhpb.EcdhKwParams{
			KeyType:   ecdhpb.KeyType_OKP,
			CurveType: c,
		},
		EncParams: &ecdhpb.EcdhAeadEncParams{
			AeadEnc: encT,
			CEK:     cek,
		},
		EcPointFormat: ptfmt,
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  0,
		KeyValue: x25519Pvt,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: 0,
			Params:  params,
			X:       x25519Pub,
		},
	}
}

// ecdhAEADPublicKey returns a EcdhAeadPublicKey with specified parameters.
func ecdhAEADPublicKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat, kt ecdhpb.KeyType,
	encT *tinkpb.KeyTemplate, x, y, cek []byte) *ecdhpb.EcdhAeadPublicKey {
	t.Helper()

	return &ecdhpb.EcdhAeadPublicKey{
		Version: 0,
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: c,
				KeyType:   kt,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: encT,
				CEK:     cek,
			},
			EcPointFormat: ptfmt,
		},
		X: x,
		Y: y,
	}
}

// ecdhesAEADPrivateKey returns a EcdhAeadPrivateKey with specified parameters.
func ecdhesAEADPrivateKey(t *testing.T, p *ecdhpb.EcdhAeadPublicKey, d []byte) *ecdhpb.EcdhAeadPrivateKey {
	t.Helper()

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:   0,
		PublicKey: p,
		KeyValue:  d,
	}
}

func TestNoopAEAD_Decrypt(t *testing.T) {
	n := noopAEAD{}

	plainText, err := n.Decrypt([]byte("test"), nil)
	require.NoError(t, err)
	require.EqualValues(t, "test", plainText)
}

func TestPrivKeyWriter_Write(t *testing.T) {
	p := privKeyWriter{}

	err := p.Write(nil)
	require.EqualError(t, err, "privKeyWriter: write function not supported")
}
