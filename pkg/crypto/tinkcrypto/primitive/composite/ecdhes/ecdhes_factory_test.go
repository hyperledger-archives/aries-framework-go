/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/stretchr/testify/require"

	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
)

func TestECDHESFactory(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryEncT := aead.AES128GCMKeyTemplate()
	rawEncT := aead.AES256GCMKeyTemplate()

	primaryPrivProto := generateECDHESAEADPrivateKey(t, c, primaryPtFmt, primaryEncT)

	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdhesPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto := generateECDHESAEADPrivateKey(t, c, rawPtFmt, rawEncT)

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
		aad := random.GetRandomBytes(10)
		ct, err := e.Encrypt(pt, aad)
		require.NoError(t, err)

		gotpt, err := d.Decrypt(ct, aad)
		require.NoError(t, err)

		require.EqualValues(t, pt, gotpt)
	}
}

// ecdhesAEADPublicKey returns a EcdhesAeadPublicKey with specified parameters.
func ecdhesAEADPublicKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat,
	encT *tinkpb.KeyTemplate, x, y []byte) *ecdhespb.EcdhesAeadPublicKey {
	t.Helper()

	return &ecdhespb.EcdhesAeadPublicKey{
		Version: 0,
		Params: &ecdhespb.EcdhesAeadParams{
			KwParams: &ecdhespb.EcdhesKwParams{
				CurveType: c,
				// add recipients for Encryption primitive
				Recipients: []*ecdhespb.EcdhesAeadRecipientPublicKey{
					{
						CurveType: c,
						X:         x,
						Y:         y,
					},
				},
			},
			EncParams: &ecdhespb.EcdhesAeadEncParams{
				AeadEnc: encT,
			},
			EcPointFormat: ptfmt,
		},
		X: x,
		Y: y,
	}
}

// eciesAEADESPrivateKey returns a EciesAeadHkdfPrivateKey with specified parameters
func eciesAEADESPrivateKey(t *testing.T, p *ecdhespb.EcdhesAeadPublicKey, d []byte) *ecdhespb.EcdhesAeadPrivateKey {
	t.Helper()

	return &ecdhespb.EcdhesAeadPrivateKey{
		Version:   0,
		PublicKey: p,
		KeyValue:  d,
	}
}

// generateECDHESAEADPrivateKey generates a new EC key pair and returns the private key proto.
func generateECDHESAEADPrivateKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat,
	encT *tinkpb.KeyTemplate) *ecdhespb.EcdhesAeadPrivateKey {
	t.Helper()

	curve, err := hybrid.GetCurve(c.String())
	require.NoError(t, err)

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	pubKey := ecdhesAEADPublicKey(t, c, ptfmt, encT, pvt.PublicKey.Point.X.Bytes(), pvt.PublicKey.Point.Y.Bytes())

	return eciesAEADESPrivateKey(t, pubKey, pvt.D.Bytes())
}

func TestECDHESFactoryWithBadKeysetType(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P384
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryEncT := aead.AES128GCMKeyTemplate()
	rawEncT := aead.AES256GCMKeyTemplate()

	primaryPrivProto := generateECDHESAEADPrivateKey(t, c, primaryPtFmt, primaryEncT)

	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdhesPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto := generateECDHESAEADPrivateKey(t, c, rawPtFmt, rawEncT)

	sRawPriv, err := proto.Marshal(rawPrivProto)
	require.NoError(t, err)

	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdhesPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	badPrivKeyProto, err := testutil.GenerateECIESAEADHKDFPrivateKey(c, commonpb.HashType_SHA256, primaryPtFmt,
		aead.AES256GCMKeyTemplate(), []byte("some salt"))
	require.NoError(t, err)

	sBadKeyPriv, err := proto.Marshal(badPrivKeyProto)
	require.NoError(t, err)

	badKeyURLKeyTypeURL := "type.bad.type.url"
	badPrivKey := testutil.NewKey(
		testutil.NewKeyData(badKeyURLKeyTypeURL, sBadKeyPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 12, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey, badPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)
	require.NotEmpty(t, khPriv)

	// calling Public() with a keyset containing an invalid key type should fail
	_, err = khPriv.Public()
	require.Error(t, err)

	// creating new primitives with an invalid keyset (should be public keyset) should fail
	e, err := NewECDHESEncrypt(khPriv)
	require.Error(t, err)
	require.Empty(t, e)

	// creating new primitives with a keyset containing an invalid key type should fail
	d, err := NewECDHESDecrypt(khPriv)
	require.Error(t, err)
	require.Empty(t, d)
}

func TestNewEncryptPrimitiveSetFail(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	primitiveSet, err := kh.Primitives()
	require.NoError(t, err)

	// calling newEncryptPrimitiveSet with non CompositeEncrypt primitiveSet should fail
	encPrimitiveSet, err := newEncryptPrimitiveSet(primitiveSet)
	require.Error(t, err)
	require.Nil(t, encPrimitiveSet)

	validKH, err := keyset.NewHandle(ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	validPubKH, err := validKH.Public()
	require.NoError(t, err)

	// primitives of a valid Public keyset.Handle do Encrypt() (while Private Handle do Decrypt())
	primitiveSet2, err := validPubKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet is successful with valid primitiveSet2 (ECDHESP256+AES256GCM enc primitive)
	encPrimitiveSet, err = newEncryptPrimitiveSet(primitiveSet2)
	require.NoError(t, err)
	require.NotEmpty(t, encPrimitiveSet)

	// create ECDSA key and add it to primitiveSet2
	key := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
	serializedKey, err := proto.Marshal(key)
	require.NoError(t, err)

	keyData := testutil.NewKeyData(testutil.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	privKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 109, tinkpb.OutputPrefixType_TINK)

	// add invalid (signing) primitive to primitiveSet2
	_, err = primitiveSet2.Add(primitiveSet.Primary.Primitive, privKey)
	require.NoError(t, err)

	// calling newEncryptPrimitiveSet with primitiveSet containing bad primitive entry should fail
	encPrimitiveSet, err = newEncryptPrimitiveSet(primitiveSet2)
	require.Error(t, err)
	require.Nil(t, encPrimitiveSet)
}

func TestEncryptPrimitiveSetFail(t *testing.T) {
	validKH, err := keyset.NewHandle(ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	validPubKH, err := validKH.Public()
	require.NoError(t, err)

	// primitives of a valid Public keyset.Handle do Encrypt() (while Private Handle do Decrypt())
	primitiveSet, err := validPubKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet is successful with valid primitiveSet2 (ECDHESP256+AES256GCM enc primitive)
	encPrimitiveSet, err := newEncryptPrimitiveSet(primitiveSet)
	require.NoError(t, err)
	require.NotEmpty(t, encPrimitiveSet)

	// Encrypt should fail as key set of primitive set do not have public recipients keys for encryption
	_, err = encPrimitiveSet.Encrypt([]byte("plaintext"), []byte("aad"))
	require.Error(t, err)

	// create ECDSA key and set encPrimitiveSet's primary primtive to the ECDSA's primary
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	sigPS, err := kh.Primitives()
	require.NoError(t, err)

	encPrimitiveSet.ps.Primary = sigPS.Primary

	_, err = encPrimitiveSet.Encrypt([]byte("plaintext"), []byte("aad"))
	require.Error(t, err)
}

func TestNewDecryptPrimitiveSetFail(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	primitiveSet, err := kh.Primitives()
	require.NoError(t, err)

	// calling newEncryptPrimitiveSet with non CompositeEncrypt primitiveSet should fail
	decPrimitiveSet, err := newDecryptPrimitiveSet(primitiveSet)
	require.Error(t, err)
	require.Nil(t, decPrimitiveSet)

	validKH, err := keyset.NewHandle(ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	// primitives of a valid Private keyset.Handle do Decrypt() (while Public Handle do Encrypt())
	primitiveSet2, err := validKH.Primitives()
	require.NoError(t, err)

	// ensure calling newDecryptPrimitiveSet is successful with valid primitiveSet2 (ECDHESP256+AES256GCM enc primitive)
	decPrimitiveSet, err = newDecryptPrimitiveSet(primitiveSet2)
	require.NoError(t, err)
	require.NotEmpty(t, decPrimitiveSet)

	// create ECDSA key and add it to primitiveSet2
	key := testutil.NewRandomECDSAPrivateKey(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256)
	serializedKey, err := proto.Marshal(key)
	require.NoError(t, err)

	keyData := testutil.NewKeyData(testutil.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	privKey := testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, 109, tinkpb.OutputPrefixType_TINK)

	// add invalid (signing) primitive to primitiveSet2
	_, err = primitiveSet2.Add(primitiveSet.Primary.Primitive, privKey)
	require.NoError(t, err)

	// calling newEncryptPrimitiveSet with primitiveSet containing bad primitive entry should fail
	decPrimitiveSet, err = newDecryptPrimitiveSet(primitiveSet2)
	require.Error(t, err)
	require.Nil(t, decPrimitiveSet)
}

func TestDecryptPrimitiveSetFail(t *testing.T) {
	validKH, err := keyset.NewHandle(ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	validPubKH, err := validKH.Public()
	require.NoError(t, err)

	// primitives of a valid Private keyset.Handle do Decrypt() (while Public Handle do Encrypt())
	primitiveSet, err := validKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet is successful with valid primitiveSet (ECDHESP256+AES256GCM enc primitive)
	decPrimitiveSet, err := newDecryptPrimitiveSet(primitiveSet)
	require.NoError(t, err)
	require.NotEmpty(t, decPrimitiveSet)

	// primitives of a valid Public Handle do Encrypt() so it should fail for newDecryptPrimitiveSet
	primitiveSetBad, err := validPubKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet is successful with valid primitiveSet2 (ECDHESP256+AES256GCM enc primitive)
	_, err = newDecryptPrimitiveSet(primitiveSetBad)
	require.Error(t, err)

	// Decrypt invalid cipher should fail
	_, err = decPrimitiveSet.Decrypt([]byte("plaintext"), []byte("aad"))
	require.Error(t, err)

	// create ECDSA key and set decPrimitiveSet's primary primtive to the ECDSA's primary
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	sigPS, err := kh.Primitives()
	require.NoError(t, err)

	// try decrypt with invalid primitive as RAW prefix (type set fail)
	decPrimitiveSet.ps.Entries[""] = []*primitiveset.Entry{sigPS.Primary}
	decPrimitiveSet.ps.Primary = sigPS.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("plaintext"), []byte("aad"))
	require.Error(t, err)

	// try decrypt with invalid primitive and prefix (type set fail)
	decPrimitiveSet.ps.Entries["12345"] = []*primitiveset.Entry{sigPS.Primary}
	decPrimitiveSet.ps.Primary = sigPS.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("12345plaintext"), []byte("aad"))
	require.Error(t, err)

	// try decrypt with valid primitiveset with raw prefix and a non raw prefix (decryption fail with valid type)
	primitiveSet, err = validKH.Primitives()
	require.NoError(t, err)

	decPrimitiveSet.ps.Entries[""] = []*primitiveset.Entry{primitiveSet.Primary}
	decPrimitiveSet.ps.Primary = primitiveSet.Primary
	decPrimitiveSet.ps.Entries["12345"] = []*primitiveset.Entry{primitiveSet.Primary}
	decPrimitiveSet.ps.Primary = primitiveSet.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("12345plaintext"), []byte("aad"))
	require.Error(t, err)
}
