/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/tink/go/aead"
	subtleaead "github.com/google/tink/go/aead/subtle"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/require"

	ecdhespb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdhes_aead_go_proto"
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

	cEnc := NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, ecdhespb.KeyType_EC)

	pt := []byte("secret message")
	aad := []byte("aad message")

	ct, err := cEnc.Encrypt(pt, aad)
	require.NoError(t, err)

	for _, privKey := range recipientsPrivKeys {
		dEnc := NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper,
			ecdhespb.KeyType_EC)

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

	// test with empty recipients public keys
	cEnc := NewECDHESAEADCompositeEncrypt(nil, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, ecdhespb.KeyType_EC)

	// Encrypt should fail with empty recipients public keys
	_, err := cEnc.Encrypt(pt, aad)
	require.Error(t, err)

	// test with large key size
	mEncHelper.KeySizeValue = 100

	cEnc = NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, ecdhespb.KeyType_EC)

	// Encrypt should fail with large AEAD key size value
	_, err = cEnc.Encrypt(pt, aad)
	require.Error(t, err)

	mEncHelper.KeySizeValue = 32

	// test with GetAEAD() returning error
	mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

	cEnc = NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, ecdhespb.KeyType_EC)

	// Encrypt should fail with large AEAD key size value
	_, err = cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, "error from GetAEAD")

	mEncHelper.AEADErrValue = nil

	// create a valid ciphertext to test Decrypt for all recipients
	cEnc = NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper, ecdhespb.KeyType_EC)

	// test with empty plaintext
	ct, err := cEnc.Encrypt([]byte{}, aad)
	require.NoError(t, err)

	encData := new(EncryptedData)
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
		dEnc := NewECDHESAEADCompositeDecrypt(nil, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper,
			ecdhespb.KeyType_EC)

		_, err = dEnc.Decrypt(ct, aad)
		require.Error(t, err)

		// test with large key size
		mEncHelper.KeySizeValue = 100
		dEnc = NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper,
			ecdhespb.KeyType_EC)

		_, err = dEnc.Decrypt(ct, aad)
		require.Error(t, err)

		mEncHelper.KeySizeValue = 32

		// test with GetAEAD() returning error
		mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

		dEnc = NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper,
			ecdhespb.KeyType_EC)

		_, err = dEnc.Decrypt(ct, aad)
		require.Error(t, err)

		mEncHelper.AEADErrValue = nil

		// create a valid Decrypt message and test against ct
		dEnc = NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper,
			ecdhespb.KeyType_EC)

		// try decrypting empty ct
		_, err = dEnc.Decrypt([]byte{}, aad)
		require.Error(t, err)

		// try decrypting with empty encAlg
		var encData EncryptedData
		err = json.Unmarshal(ct, &encData)
		require.NoError(t, err)

		encData.EncAlg = ""

		emptyAlgCiphertext, err := json.Marshal(encData)
		require.NoError(t, err)

		_, err = dEnc.Decrypt(emptyAlgCiphertext, aad)
		require.Error(t, err)

		// finally try successful decrypt
		dpt, err := dEnc.Decrypt(ct, aad)
		require.NoError(t, err)
		require.EqualValues(t, pt, dpt)
	}
}

func buildRecipientsKeys(t *testing.T, nbOfRecipients int) ([]*hybrid.ECPrivateKey, []*PublicKey) {
	t.Helper()

	var (
		recipientsECPrivKeys []*hybrid.ECPrivateKey
		recipientsPubKeys    []*PublicKey
	)

	curvProto := commonpb.EllipticCurveType_NIST_P256
	curve, err := hybrid.GetCurve(curvProto.String())
	require.NoError(t, err)

	for i := 0; i < nbOfRecipients; i++ {
		recipientPriv, err := hybrid.GenerateECDHKeyPair(curve)
		require.NoError(t, err)

		recipientPub := &recipientPriv.PublicKey

		recipientsECPrivKeys = append(recipientsECPrivKeys, recipientPriv)
		recipientsPubKeys = append(recipientsPubKeys, &PublicKey{
			Type:  ecdhespb.KeyType_EC.String(),
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

// MockEncHelper an mocked AEAD helper of Composite Encrypt/Decrypt primitives
type MockEncHelper struct {
	KeySizeValue int
	AEADValue    tink.AEAD
	AEADErrValue error
	TagSizeValue int
	IVSizeValue  int
}

// GetSymmetricKeySize gives the size of the Encryption key (CEK) in bytes
func (me *MockEncHelper) GetSymmetricKeySize() int {
	return me.KeySizeValue
}

// GetAEAD returns the newly created AEAD primitive used for the content Encryption
func (me *MockEncHelper) GetAEAD(symmetricKeyValue []byte) (tink.AEAD, error) {
	return me.AEADValue, me.AEADErrValue
}

// GetTagSize provides the aead primitive tag size
func (me *MockEncHelper) GetTagSize() int {
	return me.TagSizeValue
}

// GetIVSize provides the aead primitive nonce size
func (me *MockEncHelper) GetIVSize() int {
	return me.IVSizeValue
}
