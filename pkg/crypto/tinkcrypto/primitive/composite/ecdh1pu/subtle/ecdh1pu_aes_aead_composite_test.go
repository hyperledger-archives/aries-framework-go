/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/tink/go/aead"
	subtleaead "github.com/google/tink/go/aead/subtle"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	compositepb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/common_composite_go_proto"
)

func TestEncryptDecrypt(t *testing.T) {
	recipientsPrivKeys, recipientsPubKeys := buildRecipientsKeys(t, 10)
	aeadPrimitive := getAEADPrimitive(t, aead.AES256GCMKeyTemplate())

	mEncHelper := &MockEncHelper{
		KeySizeValue: 32,
		AEADValue:    aeadPrimitive,
		TagSizeValue: subtleaead.AESGCMTagSize,
		IVSizeValue:  subtleaead.AESGCMIVSize,
	}

	senderKey := recipientsPrivKeys[0]

	cEnc := NewECDH1PUAEADCompositeEncrypt(recipientsPubKeys, senderKey, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, compositepb.KeyType_EC)

	pt := []byte("secret message")
	aad := []byte("aad message")

	ct, err := cEnc.Encrypt(pt, aad)
	require.NoError(t, err)

	for _, privKey := range recipientsPrivKeys {
		dEnc := NewECDH1PUAEADCompositeDecrypt(&senderKey.PublicKey, privKey,
			commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper, compositepb.KeyType_EC)

		dpt, err := dEnc.Decrypt(ct, aad)
		require.NoError(t, err)
		require.EqualValues(t, pt, dpt)
	}
}

func TestEncryptDecryptNegativeTCs(t *testing.T) {
	recipientsPrivKeys, recipientsPubKeys := buildRecipientsKeys(t, 10)
	aeadPrimitive := getAEADPrimitive(t, aead.AES256GCMKeyTemplate())

	mEncHelper := &MockEncHelper{
		KeySizeValue: 32,
		AEADValue:    aeadPrimitive,
		TagSizeValue: subtleaead.AESGCMTagSize,
		IVSizeValue:  subtleaead.AESGCMIVSize,
	}

	pt := []byte("secret message")
	aad := []byte("aad message")

	senderKey := recipientsPrivKeys[0]

	// test with empty recipients public keys
	cEnc := NewECDH1PUAEADCompositeEncrypt(nil, senderKey, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, compositepb.KeyType_EC)

	// Encrypt should fail with empty recipients public keys
	_, err := cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, "ECDH1PUAEADCompositeEncrypt: missing recipients public keys for key wrapping")

	// test with large key size
	mEncHelper.KeySizeValue = 100

	cEnc = NewECDH1PUAEADCompositeEncrypt(recipientsPubKeys, senderKey, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, compositepb.KeyType_EC)

	// Encrypt should fail with large AEAD key size value
	_, err = cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, "crypto/aes: invalid key size 100")

	mEncHelper.KeySizeValue = 32

	// Encrypt should fail with bad key type
	cEnc.keyType = compositepb.KeyType_UNKNOWN_KEY_TYPE

	_, err = cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, fmt.Sprintf("ECDH1PUAEADCompositeEncrypt: bad key type: '%s'",
		compositepb.KeyType_UNKNOWN_KEY_TYPE))

	cEnc.keyType = compositepb.KeyType_EC

	// test with GetAEAD() returning error
	mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

	cEnc = NewECDH1PUAEADCompositeEncrypt(recipientsPubKeys, senderKey, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, compositepb.KeyType_EC)

	// Encrypt should fail with large AEAD key size value
	_, err = cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, "error from GetAEAD")

	mEncHelper.AEADErrValue = nil

	// create a valid ciphertext to test Decrypt for all recipients
	cEnc = NewECDH1PUAEADCompositeEncrypt(recipientsPubKeys, senderKey, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, compositepb.KeyType_EC)

	// test with empty plaintext
	ct, err := cEnc.Encrypt([]byte{}, aad)
	require.NoError(t, err)

	encData := new(composite.EncryptedData)
	err = json.Unmarshal(ct, encData)

	require.NoError(t, err)
	// encrypting empty plaintext should result in empty ciphertext
	require.Empty(t, encData.Ciphertext)
	require.Len(t, encData.Tag, subtleaead.AESGCMTagSize)
	require.Len(t, encData.IV, subtleaead.AESGCMIVSize)

	ct, err = cEnc.Encrypt(pt, aad)
	require.NoError(t, err)

	for _, privKey := range recipientsPrivKeys {
		// test with nil recipient private key
		dEnc := NewECDH1PUAEADCompositeDecrypt(nil, nil, commonpb.EcPointFormat_UNCOMPRESSED.String(),
			mEncHelper, compositepb.KeyType_EC)

		_, err = dEnc.Decrypt(ct, aad)
		require.EqualError(t, err, "ECDH1PUAEADCompositeDecrypt: missing recipient private key for key"+
			" unwrapping")

		// test with large key size
		mEncHelper.KeySizeValue = 100
		dEnc = NewECDH1PUAEADCompositeDecrypt(&senderKey.PublicKey, privKey,
			commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper, compositepb.KeyType_EC)

		_, err = dEnc.Decrypt(ct, aad)
		require.EqualError(t, err, "ecdh-1pu decrypt: cek unwrap failed for all recipients keys")

		mEncHelper.KeySizeValue = 32

		// test with GetAEAD() returning error
		mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

		dEnc = NewECDH1PUAEADCompositeDecrypt(&senderKey.PublicKey, privKey,
			commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper, compositepb.KeyType_EC)

		_, err = dEnc.Decrypt(ct, aad)
		require.EqualError(t, err, "error from GetAEAD")

		mEncHelper.AEADErrValue = nil

		// create a valid Decrypt message and test against ct
		dEnc = NewECDH1PUAEADCompositeDecrypt(&senderKey.PublicKey, privKey,
			commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper, compositepb.KeyType_EC)

		// try decrypting empty ct
		_, err = dEnc.Decrypt([]byte{}, aad)
		require.EqualError(t, err, "unexpected end of JSON input")

		// try decrypting with empty encAlg
		var encData composite.EncryptedData
		err = json.Unmarshal(ct, &encData)
		require.NoError(t, err)

		encData.EncAlg = ""

		emptyAlgCiphertext, err := json.Marshal(encData)
		require.NoError(t, err)

		_, err = dEnc.Decrypt(emptyAlgCiphertext, aad)
		require.EqualError(t, err, "invalid content encryption algorihm '' for Decrypt()")

		// finally try successful decrypt
		dpt, err := dEnc.Decrypt(ct, aad)
		require.NoError(t, err)
		require.EqualValues(t, pt, dpt)
	}
}

func TestEncryptDecryptWithSingleRecipient(t *testing.T) {
	recipientsPrivKeys, recipientsPubKeys := buildRecipientsKeys(t, 1)
	aeadPrimitive := getAEADPrimitive(t, aead.AES256GCMKeyTemplate())

	mEncHelper := &MockEncHelper{
		KeySizeValue: 32,
		AEADValue:    aeadPrimitive,
		TagSizeValue: subtleaead.AESGCMTagSize,
		IVSizeValue:  subtleaead.AESGCMIVSize,
	}

	pt := []byte("secret message")
	aad := []byte("aad message")

	senderKey := recipientsPrivKeys[0]

	// test with single recipient public key
	cEnc := NewECDH1PUAEADCompositeEncrypt(recipientsPubKeys, senderKey, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, compositepb.KeyType_EC)

	errMsg := "error merge recipient headers"
	mEncHelper.MergeRecErr = fmt.Errorf(errMsg)

	// Encrypt should fail with errMsg
	_, err := cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, errMsg)

	newAAD := base64.RawURLEncoding.EncodeToString([]byte("{\"enc\":\"testAlg\"}"))
	mEncHelper.MergeRecErr = nil
	mEncHelper.MergeRecValue = []byte(newAAD)

	// Encrypt should pass with base64Url encoded a valid json marshaled aad
	ct, err := cEnc.Encrypt(pt, []byte(newAAD))
	require.NoError(t, err)

	encData := &composite.EncryptedData{}
	err = json.Unmarshal(ct, encData)
	require.NoError(t, err)

	for _, privKey := range recipientsPrivKeys {
		dEnc := NewECDH1PUAEADCompositeDecrypt(&senderKey.PublicKey, privKey,
			commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper, compositepb.KeyType_EC)

		dpt, err := dEnc.Decrypt(ct, encData.SingleRecipientAAD)
		require.NoError(t, err)
		require.EqualValues(t, pt, dpt)
	}
}

func buildRecipientsKeys(t *testing.T, nbOfRecipients int) ([]*hybrid.ECPrivateKey, []*composite.PublicKey) {
	t.Helper()

	var (
		recipientsECPrivKeys []*hybrid.ECPrivateKey
		recipientsPubKeys    []*composite.PublicKey
	)

	curvProto := commonpb.EllipticCurveType_NIST_P256
	curve, err := hybrid.GetCurve(curvProto.String())
	require.NoError(t, err)

	for i := 0; i < nbOfRecipients; i++ {
		recipientPriv, err := hybrid.GenerateECDHKeyPair(curve)
		require.NoError(t, err)

		recipientPub := &recipientPriv.PublicKey

		recipientsECPrivKeys = append(recipientsECPrivKeys, recipientPriv)
		recipientsPubKeys = append(recipientsPubKeys, &composite.PublicKey{
			Type:  compositepb.KeyType_EC.String(),
			Curve: recipientPub.Curve.Params().Name,
			X:     recipientPub.Point.X.Bytes(),
			Y:     recipientPub.Point.Y.Bytes(),
		})
	}

	return recipientsECPrivKeys, recipientsPubKeys
}

func getAEADPrimitive(t *testing.T, kt *tinkpb.KeyTemplate) tink.AEAD {
	t.Helper()

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	ps, err := kh.Primitives()
	require.NoError(t, err)

	p, ok := (ps.Primary.Primitive).(tink.AEAD)
	require.True(t, ok)

	return p
}

// MockEncHelper an mocked AEAD helper of Composite Encrypt/Decrypt primitives.
type MockEncHelper struct {
	KeySizeValue  int
	AEADValue     tink.AEAD
	AEADErrValue  error
	TagSizeValue  int
	IVSizeValue   int
	MergeRecValue []byte
	MergeRecErr   error
}

// GetSymmetricKeySize gives the size of the Encryption key (CEK) in bytes.
func (m *MockEncHelper) GetSymmetricKeySize() int {
	return m.KeySizeValue
}

// GetAEAD returns the newly created AEAD primitive used for the content Encryption.
func (m *MockEncHelper) GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error) {
	return m.AEADValue, m.AEADErrValue
}

// GetTagSize provides the aead primitive tag size.
func (m *MockEncHelper) GetTagSize() int {
	return m.TagSizeValue
}

// GetIVSize provides the aead primitive nonce size.
func (m *MockEncHelper) GetIVSize() int {
	return m.IVSizeValue
}

// BuildEncData will build the []byte representing the ciphertext sent to the end user of the Composite primitive.
func (m *MockEncHelper) BuildEncData(eAlg, eTyp string, recipientsWK []*composite.RecipientWrappedKey, ct,
	singleRecipientAAD []byte) ([]byte, error) {
	tagSize := m.GetTagSize()
	ivSize := m.GetIVSize()
	iv := ct[:ivSize]
	ctAndTag := ct[ivSize:]
	tagOffset := len(ctAndTag) - tagSize

	encData := &composite.EncryptedData{
		EncAlg:             eAlg,
		EncType:            eTyp,
		Ciphertext:         ctAndTag[:tagOffset],
		IV:                 iv,
		Tag:                ctAndTag[tagOffset:],
		Recipients:         recipientsWK,
		SingleRecipientAAD: singleRecipientAAD,
	}

	return json.Marshal(encData)
}

func (m *MockEncHelper) MergeSingleRecipientHeaders(_ *composite.RecipientWrappedKey, aad []byte) ([]byte, error) {
	return m.MergeRecValue, m.MergeRecErr
}

// BuildDecData will build the []byte representing the ciphertext coming from encData struct returned as a result of
// Composite Encrypt() call to prepare the Composite Decryption primitive execution.
func (m *MockEncHelper) BuildDecData(encData *composite.EncryptedData) []byte {
	iv := encData.IV
	tag := encData.Tag
	ct := encData.Ciphertext
	finalCT := append(iv, ct...)
	finalCT = append(finalCT, tag...)

	return finalCT
}

func TestUnWrapUsingKeysOnDifferentCurves(t *testing.T) {
	keySize := 32
	curveP256, err := hybrid.GetCurve(commonpb.EllipticCurveType_NIST_P256.String())
	require.NoError(t, err)

	curveP384, err := hybrid.GetCurve(commonpb.EllipticCurveType_NIST_P384.String())
	require.NoError(t, err)

	recPvt, err := hybrid.GenerateECDHKeyPair(curveP256)
	require.NoError(t, err)

	recPubKey := &composite.PublicKey{
		Type:  compositepb.KeyType_EC.String(),
		Curve: recPvt.PublicKey.Curve.Params().Name,
		X:     recPvt.PublicKey.Point.X.Bytes(),
		Y:     recPvt.PublicKey.Point.Y.Bytes(),
	}

	// try to wrap a key on a different curve
	badSenderPvt2, err := hybrid.GenerateECDHKeyPair(curveP384)
	require.NoError(t, err)

	senderKW := &ECDH1PUConcatKDFSenderKW{
		senderPrivateKey:   badSenderPvt2,
		recipientPublicKey: recPubKey,
		cek:                random.GetRandomBytes(uint32(keySize)),
	}

	wrappedKey, err := senderKW.wrapKey(A256KWAlg, keySize)
	require.EqualError(t, err, "unwrapKey: recipient and sender keys are not on the same curve")
	require.Nil(t, wrappedKey)

	senderPvt, err := hybrid.GenerateECDHKeyPair(curveP256)
	require.NoError(t, err)

	// now wrap with keys on the same curve
	senderKW = &ECDH1PUConcatKDFSenderKW{
		senderPrivateKey:   senderPvt,
		recipientPublicKey: recPubKey,
		cek:                random.GetRandomBytes(uint32(keySize)),
	}

	wrappedKey, err = senderKW.wrapKey(A256KWAlg, keySize)
	require.NoError(t, err)
	require.NotEmpty(t, wrappedKey)
	require.EqualValues(t, A256KWAlg, wrappedKey.Alg)

	senderPub := &hybrid.ECPublicKey{
		Point: hybrid.ECPoint{
			X: senderPvt.PublicKey.Point.X,
			Y: senderPvt.PublicKey.Point.Y,
		},
		Curve: senderPvt.PublicKey.Curve,
	}

	recipientKW := &ECDH1PUConcatKDFRecipientKW{
		senderPubKey:        senderPub,
		recipientPrivateKey: recPvt,
	}

	cek, err := recipientKW.unwrapKey(wrappedKey, keySize)
	require.NoError(t, err)
	require.EqualValues(t, senderKW.cek, cek)

	// error test cases
	_, err = recipientKW.unwrapKey(nil, keySize)
	require.Error(t, err)

	// change recPvt curve to trigger an error during unwrapKey
	recPvt.PublicKey.Curve = curveP384

	recipientKW = &ECDH1PUConcatKDFRecipientKW{
		senderPubKey:        senderPub,
		recipientPrivateKey: recPvt,
	}

	cek, err = recipientKW.unwrapKey(wrappedKey, keySize)
	require.EqualError(t, err, "unwrapKey: recipient and sender keys are not on the same curve")
	require.Empty(t, cek)
}
