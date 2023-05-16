/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/primitiveset"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

func TestECDHESFactory(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryEncT := aead.AES128GCMKeyTemplate()
	rawEncT := aead.AES256GCMKeyTemplate()
	kt := ecdhpb.KeyType_EC
	cek := random.GetRandomBytes(32)

	primaryPrivProto := generateECDHAEADPrivateKey(t, c, primaryPtFmt, kt, primaryEncT, cek)

	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto := generateECDHAEADPrivateKey(t, c, rawPtFmt, kt, rawEncT, cek)

	sRawPriv, err := proto.Marshal(rawPrivProto)
	require.NoError(t, err)

	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	x25519XChachaPrivProto := generateECDHAEADPrivateKey(t, commonpb.EllipticCurveType_CURVE25519, primaryPtFmt,
		ecdhpb.KeyType_OKP, aead.XChaCha20Poly1305KeyTemplate(), cek)

	sX25519XChachaPriv, err := proto.Marshal(x25519XChachaPrivProto)
	require.NoError(t, err)

	x25519XChachaPrivKey := testutil.NewKey(
		testutil.NewKeyData(x25519ECDHKWPrivateKeyTypeURL, sX25519XChachaPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 15, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey, x25519XChachaPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)

	xPrivKeys := []*tinkpb.Keyset_Key{x25519XChachaPrivKey, rawPrivKey, primaryPrivKey}
	xPrivKeyset := testutil.NewKeyset(xPrivKeys[0].KeyId, xPrivKeys)
	xKHPriv, err := testkeyset.NewHandle(xPrivKeyset)
	require.NoError(t, err)

	khPub, err := khPriv.Public()
	require.NoError(t, err)

	xKHPub, err := xKHPriv.Public()
	require.NoError(t, err)

	e, err := NewECDHEncrypt(khPub)
	require.NoError(t, err)

	d, err := NewECDHDecrypt(khPriv)
	require.NoError(t, err)

	xe, err := NewECDHEncrypt(xKHPub)
	require.NoError(t, err)

	xd, err := NewECDHDecrypt(xKHPriv)
	require.NoError(t, err)

	for i := 0; i < 1000; i++ {
		pt := random.GetRandomBytes(20)
		aadRndNb := random.GetRandomBytes(10)

		// single recipient requires aad to be a valid marshaled JSON base64URL encoded
		// since the encryption primitive now appends the recipient's headers to aad prior to encryption
		// this is not required for multiple recipient encryption since aad does not include recipients headers.
		aadJSON, err := json.Marshal(aadRndNb)
		require.NoError(t, err)

		aad, err := json.Marshal(&map[string]interface{}{"someFiled": json.RawMessage(aadJSON)})
		require.NoError(t, err)

		aadStr := base64.RawURLEncoding.EncodeToString(aad)
		aad = []byte(aadStr)

		ct, err := e.Encrypt(pt, aad)
		require.NoError(t, err)

		xct, err := xe.Encrypt(pt, aad)
		require.NoError(t, err)

		// encrypt for single recipient will generate new AAD for recipient, extract it from ct
		encData := &composite.EncryptedData{}
		err = json.Unmarshal(ct, encData)
		require.NoError(t, err)

		gotpt, err := d.Decrypt(ct, aad)
		require.NoError(t, err)

		xgotpt, err := xd.Decrypt(xct, aad)
		require.NoError(t, err)

		require.EqualValues(t, pt, gotpt)
		require.EqualValues(t, pt, xgotpt)
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

// generateECDHAEADPrivateKey generates a new EC key pair and returns the private key proto.
func generateECDHAEADPrivateKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat,
	kt ecdhpb.KeyType, encT *tinkpb.KeyTemplate, cek []byte) *ecdhpb.EcdhAeadPrivateKey {
	t.Helper()

	if ecdhpb.KeyType_OKP.String() == kt.String() {
		return buildXChachaKey(t, ptfmt, encT, c, cek)
	}

	curve, err := hybrid.GetCurve(c.String())
	require.NoError(t, err)

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	pubKey := ecdhAEADPublicKey(t, c, ptfmt, kt, encT, pvt.PublicKey.Point.X.Bytes(), pvt.PublicKey.Point.Y.Bytes(),
		cek)

	return ecdhesAEADPrivateKey(t, pubKey, pvt.D.Bytes())
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

func TestECDHESFactoryWithBadKeysetType(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P384
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryEncT := aead.AES128GCMKeyTemplate()
	rawEncT := aead.AES256GCMKeyTemplate()
	kt := ecdhpb.KeyType_EC
	cek := random.GetRandomBytes(32)

	primaryPrivProto := generateECDHAEADPrivateKey(t, c, primaryPtFmt, kt, primaryEncT, cek)

	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto := generateECDHAEADPrivateKey(t, c, rawPtFmt, kt, rawEncT, cek)

	sRawPriv, err := proto.Marshal(rawPrivProto)
	require.NoError(t, err)

	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistpECDHKWPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
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
	require.EqualError(t, err, fmt.Sprintf("keyset.Handle: registry.GetKeyManager: unsupported key type: %s",
		badKeyURLKeyTypeURL))

	// creating new primitives with an invalid keyset (should be public keyset) should fail
	e, err := NewECDHEncrypt(khPriv)
	require.EqualError(t, err, fmt.Sprintf("ecdh_factory: cannot obtain primitive set: "+
		"registry.PrimitivesWithKeyManager: cannot get primitive from key: registry.GetKeyManager: "+
		"unsupported key type: %s",
		badKeyURLKeyTypeURL))
	require.Empty(t, e)

	// creating new primitives with a keyset containing an invalid key type should fail
	d, err := NewECDHDecrypt(khPriv)
	require.EqualError(t, err, fmt.Sprintf("ecdh_factory: cannot obtain primitive set: "+
		"registry.PrimitivesWithKeyManager: cannot get primitive from key: registry.GetKeyManager: "+
		"unsupported key type: %s",
		badKeyURLKeyTypeURL))
	require.Empty(t, d)
}

func TestNewEncryptPrimitiveSetFail(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	primitiveSet, err := kh.Primitives()
	require.NoError(t, err)

	// calling newEncryptPrimitiveSet with non CompositeEncrypt primitiveSet should fail
	encPrimitiveSet, err := newEncryptPrimitiveSet(primitiveSet)
	require.EqualError(t, err, "ecdh_factory: not a CompositeEncrypt primitive")
	require.Nil(t, encPrimitiveSet)

	validKH, err := keyset.NewHandle(NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	validPubKH, err := validKH.Public()
	require.NoError(t, err)

	// primitives of a valid Public keyset.Handle do Encrypt() (while Private Handle do Decrypt())
	primitiveSet2, err := validPubKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet is successful with valid primitiveSet2
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
	require.EqualError(t, err, "ecdh_factory: not a CompositeEncrypt primitive")
	require.Nil(t, encPrimitiveSet)
}

func TestEncryptPrimitiveSetFail(t *testing.T) {
	validKH, err := keyset.NewHandle(NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	validPubKH, err := validKH.Public()
	require.NoError(t, err)

	// primitives of a valid Public keyset.Handle do Encrypt() (while Private Handle do Decrypt())
	primitiveSet, err := validPubKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet is successful with valid primitiveSet
	encPrimitiveSet, err := newEncryptPrimitiveSet(primitiveSet)
	require.NoError(t, err)
	require.NotEmpty(t, encPrimitiveSet)

	// Encrypt should fail as key set of primitive set do not have cek set
	_, err = encPrimitiveSet.Encrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdhAEADCompositeEncrypt: missing cek")

	// create ECDSA key and set encPrimitiveSet's primary primitive to the ECDSA's primary
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	sigPS, err := kh.Primitives()
	require.NoError(t, err)

	encPrimitiveSet.ps.Primary = sigPS.Primary

	// encrypting with signing key should fail
	_, err = encPrimitiveSet.Encrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh_factory: not a CompositeEncrypt primitive")
}

func TestNewDecryptPrimitiveSetFail(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	primitiveSet, err := kh.Primitives()
	require.NoError(t, err)

	// calling newEncryptPrimitiveSet with non CompositeEncrypt primitiveSet should fail
	decPrimitiveSet, err := newDecryptPrimitiveSet(primitiveSet)
	require.EqualError(t, err, "ecdh_factory: not a CompositeDecrypt primitive")
	require.Nil(t, decPrimitiveSet)

	validKH, err := keyset.NewHandle(NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	// primitives of a valid Private keyset.Handle do Decrypt() (while Public Handle do Encrypt())
	primitiveSet2, err := validKH.Primitives()
	require.NoError(t, err)

	// ensure calling newDecryptPrimitiveSet is successful with valid primitiveSet2
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
	require.EqualError(t, err, "ecdh_factory: not a CompositeDecrypt primitive")
	require.Nil(t, decPrimitiveSet)
}

func TestDecryptPrimitiveSetFail(t *testing.T) {
	validKH, err := keyset.NewHandle(NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	validPubKH, err := validKH.Public()
	require.NoError(t, err)

	// primitives of a valid Private keyset.Handle do Decrypt() (while Public Handle do Encrypt())
	primitiveSet, err := validKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet is successful with valid primitiveSet
	decPrimitiveSet, err := newDecryptPrimitiveSet(primitiveSet)
	require.NoError(t, err)
	require.NotEmpty(t, decPrimitiveSet)

	// primitives of a valid Public Handle do Encrypt() so it should fail for newDecryptPrimitiveSet
	primitiveSetBad, err := validPubKH.Primitives()
	require.NoError(t, err)

	// ensure calling newEncryptPrimitiveSet fails with invalid primitiveSetBad
	_, err = newDecryptPrimitiveSet(primitiveSetBad)
	require.EqualError(t, err, "ecdh_factory: not a CompositeDecrypt primitive")

	// Decrypt invalid cipher should fail
	_, err = decPrimitiveSet.Decrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh_factory: decryption failed")

	// create ECDSA key and set decPrimitiveSet's primary primtive to the ECDSA's primary
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	sigPS, err := kh.Primitives()
	require.NoError(t, err)

	// try decrypt with invalid primitive as RAW prefix (type set fail)
	decPrimitiveSet.ps.Entries[""] = []*primitiveset.Entry{sigPS.Primary}
	decPrimitiveSet.ps.Primary = sigPS.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh_factory: not a CompositeDecrypt primitive")

	// try decrypt with invalid primitive and prefix (type set fail)
	decPrimitiveSet.ps.Entries["12345"] = []*primitiveset.Entry{sigPS.Primary}
	decPrimitiveSet.ps.Primary = sigPS.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("12345plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh_factory: not a CompositeDecrypt primitive")

	// try decrypt with valid primitiveset with raw prefix and a non raw prefix (decryption fail with valid type)
	primitiveSet, err = validKH.Primitives()
	require.NoError(t, err)

	decPrimitiveSet.ps.Entries[""] = []*primitiveset.Entry{primitiveSet.Primary}
	decPrimitiveSet.ps.Primary = primitiveSet.Primary
	decPrimitiveSet.ps.Entries["12345"] = []*primitiveset.Entry{primitiveSet.Primary}
	decPrimitiveSet.ps.Primary = primitiveSet.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("12345plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh_factory: decryption failed")
}
