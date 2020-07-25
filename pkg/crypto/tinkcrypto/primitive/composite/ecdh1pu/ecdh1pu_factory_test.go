/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

import (
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

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
	ecdh1pupb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh1pu_aead_go_proto"
)

func TestECDH1PUFactory(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P256
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryEncT := aead.AES128GCMKeyTemplate()
	rawEncT := aead.AES256GCMKeyTemplate()

	primaryPrivProto := generateECDH1PUAEADPrivateKey(t, c, primaryPtFmt, primaryEncT)

	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdh1puAESPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto := generateECDH1PUAEADPrivateKey(t, c, rawPtFmt, rawEncT)

	sRawPriv, err := proto.Marshal(rawPrivProto)
	require.NoError(t, err)

	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdh1puAESPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 11, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{primaryPrivKey, rawPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	khPriv, err := testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)

	khPub, err := khPriv.Public()
	require.NoError(t, err)

	e, err := NewECDH1PUEncrypt(khPub)
	require.NoError(t, err)

	d, err := NewECDH1PUDecrypt(khPriv)
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

		// encrypt for single recipient will generate new AAD for recipient, extract it from ct
		encData := &composite.EncryptedData{}
		err = json.Unmarshal(ct, encData)
		require.NoError(t, err)

		gotpt, err := d.Decrypt(ct, encData.SingleRecipientAAD)
		require.NoError(t, err)

		require.EqualValues(t, pt, gotpt)
	}
}

// ecdh1puAEADPublicKey returns a Ecdh1PuAeadPublicKey with specified parameters.
func ecdh1puAEADPublicKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat,
	encT *tinkpb.KeyTemplate, x, y []byte) *ecdh1pupb.Ecdh1PuAeadPublicKey {
	t.Helper()

	return &ecdh1pupb.Ecdh1PuAeadPublicKey{
		Version: 0,
		Params: &ecdh1pupb.Ecdh1PuAeadParams{
			KwParams: &ecdh1pupb.Ecdh1PuKwParams{
				CurveType: c,
				// add recipients for Encryption primitive
				Recipients: []*compositepb.ECPublicKey{
					{
						KeyType:   compositepb.KeyType_EC,
						CurveType: c,
						X:         x,
						Y:         y,
					},
				},
				// the sender is the same as the recipient for the unit tests in this file
				Sender: &compositepb.ECPublicKey{
					CurveType: c,
					X:         x,
					Y:         y,
				},
			},
			EncParams: &ecdh1pupb.Ecdh1PuAeadEncParams{
				AeadEnc: encT,
			},
			EcPointFormat: ptfmt,
		},
		X: x,
		Y: y,
	}
}

// ecdh1puPrivateKey returns a Ecdh1PuAeadPrivateKey with specified parameters.
func ecdh1puPrivateKey(t *testing.T, p *ecdh1pupb.Ecdh1PuAeadPublicKey, d []byte) *ecdh1pupb.Ecdh1PuAeadPrivateKey {
	t.Helper()

	// key wrapping is done using the same private key in these tests, add it here for primitive execution success
	// in prod code, the key manager will set this field.
	p.KWD = d

	return &ecdh1pupb.Ecdh1PuAeadPrivateKey{
		Version:   0,
		PublicKey: p,
		KeyValue:  d,
	}
}

// generateECDH1PUAEADPrivateKey generates a new EC key pair and returns the private key proto.
func generateECDH1PUAEADPrivateKey(t *testing.T, c commonpb.EllipticCurveType, ptfmt commonpb.EcPointFormat,
	encT *tinkpb.KeyTemplate) *ecdh1pupb.Ecdh1PuAeadPrivateKey {
	t.Helper()

	curve, err := hybrid.GetCurve(c.String())
	require.NoError(t, err)

	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	require.NoError(t, err)

	pubKey := ecdh1puAEADPublicKey(t, c, ptfmt, encT, pvt.PublicKey.Point.X.Bytes(), pvt.PublicKey.Point.Y.Bytes())

	return ecdh1puPrivateKey(t, pubKey, pvt.D.Bytes())
}

func TestECDH1PUFactoryWithBadKeysetType(t *testing.T) {
	c := commonpb.EllipticCurveType_NIST_P384
	primaryPtFmt := commonpb.EcPointFormat_UNCOMPRESSED
	rawPtFmt := commonpb.EcPointFormat_COMPRESSED
	primaryEncT := aead.AES128GCMKeyTemplate()
	rawEncT := aead.AES256GCMKeyTemplate()

	primaryPrivProto := generateECDH1PUAEADPrivateKey(t, c, primaryPtFmt, primaryEncT)

	sPrimaryPriv, err := proto.Marshal(primaryPrivProto)
	require.NoError(t, err)

	primaryPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdh1puAESPrivateKeyTypeURL, sPrimaryPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 8, tinkpb.OutputPrefixType_RAW)

	rawPrivProto := generateECDH1PUAEADPrivateKey(t, c, rawPtFmt, rawEncT)

	sRawPriv, err := proto.Marshal(rawPrivProto)
	require.NoError(t, err)

	rawPrivKey := testutil.NewKey(
		testutil.NewKeyData(ecdh1puAESPrivateKeyTypeURL, sRawPriv, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
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
	e, err := NewECDH1PUEncrypt(khPriv)
	require.EqualError(t, err, fmt.Sprintf("ecdh1pu_factory: cannot obtain primitive set: "+
		"registry.PrimitivesWithKeyManager: cannot get primitive from key: registry.GetKeyManager: "+
		"unsupported key type: %s",
		badKeyURLKeyTypeURL))
	require.Empty(t, e)

	// creating new primitives with a keyset containing an invalid key type should fail
	d, err := NewECDH1PUDecrypt(khPriv)
	require.EqualError(t, err, fmt.Sprintf("ecdh1pu_factory: cannot obtain primitive set: "+
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
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeEncrypt primitive")
	require.Nil(t, encPrimitiveSet)

	validKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
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
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeEncrypt primitive")
	require.Nil(t, encPrimitiveSet)
}

func TestEncryptPrimitiveSetFail(t *testing.T) {
	validKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
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

	// Encrypt should fail as key set of primitive set do not have public recipients keys for encryption
	_, err = encPrimitiveSet.Encrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ECDH1PUAEADCompositeEncrypt: missing recipients public keys for key wrapping")

	// create ECDSA key and set encPrimitiveSet's primary primitive to the ECDSA's primary
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	sigPS, err := kh.Primitives()
	require.NoError(t, err)

	encPrimitiveSet.ps.Primary = sigPS.Primary

	// encrypting with signing key should fail
	_, err = encPrimitiveSet.Encrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeEncrypt primitive")
}

func TestNewDecryptPrimitiveSetFail(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	primitiveSet, err := kh.Primitives()
	require.NoError(t, err)

	// calling newEncryptPrimitiveSet with non CompositeEncrypt primitiveSet should fail
	decPrimitiveSet, err := newDecryptPrimitiveSet(primitiveSet)
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeDecrypt primitive")
	require.Nil(t, decPrimitiveSet)

	invalidKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	// primitives of a Private keyset.Handle fails to Decrypt() without sender key
	_, err = invalidKH.Primitives()
	require.EqualError(t, err, "registry.PrimitivesWithKeyManager: cannot get primitive from key: "+
		"ecdh1pu_aes_private_key_manager: sender public key is required for primitive execution")

	// create a key template with a sender key
	kt := ECDH1PU256KWAES256GCMKeyTemplate()
	addRandomSenderKeyToKeyTemplate(t, kt)

	validKH, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	// now calling Primitives() should not fail since it has a sender key
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
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeDecrypt primitive")
	require.Nil(t, decPrimitiveSet)
}

func addRandomSenderKeyToKeyTemplate(t *testing.T, kt *tinkpb.KeyTemplate) {
	t.Helper()

	keyFmt := new(ecdh1pupb.Ecdh1PuAeadKeyFormat)
	err := proto.Unmarshal(kt.Value, keyFmt)
	require.NoError(t, err)

	keyFmt.Params.KwParams.Sender = &compositepb.ECPublicKey{
		X:         []byte{},
		Y:         []byte{},
		CurveType: commonpb.EllipticCurveType_NIST_P256,
		KeyType:   compositepb.KeyType_EC,
		KID:       "123",
	}

	// now update key template with sender public key
	kt.Value, err = proto.Marshal(keyFmt)
	require.NoError(t, err)
}

func TestDecryptPrimitiveSetFail(t *testing.T) {
	kt := ECDH1PU256KWAES256GCMKeyTemplate()
	addRandomSenderKeyToKeyTemplate(t, kt)

	validKH, err := keyset.NewHandle(kt)
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

	// ensure calling newEncryptPrimitiveSet is failing with valid primitiveSetBad
	_, err = newDecryptPrimitiveSet(primitiveSetBad)
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeDecrypt primitive")

	// Decrypt invalid cipher should fail
	_, err = decPrimitiveSet.Decrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh1pu_factory: decryption failed")

	// create ECDSA key and set decPrimitiveSet's primary primtive to the ECDSA's primary
	kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	sigPS, err := kh.Primitives()
	require.NoError(t, err)

	// try decrypt with invalid primitive as RAW prefix (type set fail)
	decPrimitiveSet.ps.Entries[""] = []*primitiveset.Entry{sigPS.Primary}
	decPrimitiveSet.ps.Primary = sigPS.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeDecrypt primitive")

	// try decrypt with invalid primitive and prefix (type set fail)
	decPrimitiveSet.ps.Entries["12345"] = []*primitiveset.Entry{sigPS.Primary}
	decPrimitiveSet.ps.Primary = sigPS.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("12345plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh1pu_factory: not a CompositeDecrypt primitive")

	// try decrypt with valid primitiveset with raw prefix and a non raw prefix (decryption fail with valid type)
	primitiveSet, err = validKH.Primitives()
	require.NoError(t, err)

	decPrimitiveSet.ps.Entries[""] = []*primitiveset.Entry{primitiveSet.Primary}
	decPrimitiveSet.ps.Primary = primitiveSet.Primary
	decPrimitiveSet.ps.Entries["12345"] = []*primitiveset.Entry{primitiveSet.Primary}
	decPrimitiveSet.ps.Primary = primitiveSet.Primary

	_, err = decPrimitiveSet.Decrypt([]byte("12345plaintext"), []byte("aad"))
	require.EqualError(t, err, "ecdh1pu_factory: decryption failed")
}
