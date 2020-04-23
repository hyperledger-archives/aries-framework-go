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
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	subtleaead "github.com/google/tink/go/subtle/aead"
	"github.com/google/tink/go/subtle/hybrid"
	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/require"
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

	cEnc, err := NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper)
	require.NoError(t, err)

	pt := []byte("secret message")
	aad := []byte("aad message")

	ct, err := cEnc.Encrypt(pt, aad)
	require.NoError(t, err)

	for _, privKey := range recipientsPrivKeys {
		dEnc, err := NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper)
		require.NoError(t, err)

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
	cEnc, err := NewECDHESAEADCompositeEncrypt(nil, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper)
	require.NoError(t, err)

	// Encrypt should fail with empty recipients public keys
	_, err = cEnc.Encrypt(pt, aad)
	require.Error(t, err)

	// test with large key size
	mEncHelper.KeySizeValue = 100

	cEnc, err = NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper)
	require.NoError(t, err)

	// Encrypt should fail with large AEAD key size value
	_, err = cEnc.Encrypt(pt, aad)
	require.Error(t, err)

	mEncHelper.KeySizeValue = 32

	// test with GetAEAD() returning error
	mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

	cEnc, err = NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper)
	require.NoError(t, err)

	// Encrypt should fail with large AEAD key size value
	_, err = cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, "error from GetAEAD")

	mEncHelper.AEADErrValue = nil

	// create a valid ciphertext to test Decrypt for all recipients
	cEnc, err = NewECDHESAEADCompositeEncrypt(recipientsPubKeys, commonpb.EcPointFormat_UNCOMPRESSED.String(),
		mEncHelper)
	require.NoError(t, err)

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
		dEnc, err := NewECDHESAEADCompositeDecrypt(nil, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper)
		require.NoError(t, err)

		_, err = dEnc.Decrypt(ct, aad)
		require.Error(t, err)

		// test with large key size
		mEncHelper.KeySizeValue = 100
		dEnc, err = NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper)
		require.NoError(t, err)

		_, err = dEnc.Decrypt(ct, aad)
		require.Error(t, err)

		mEncHelper.KeySizeValue = 32

		// test with GetAEAD() returning error
		mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

		dEnc, err = NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper)
		require.NoError(t, err)

		_, err = dEnc.Decrypt(ct, aad)
		require.Error(t, err)

		mEncHelper.AEADErrValue = nil

		// create a valid Decrypt message and test against ct
		dEnc, err = NewECDHESAEADCompositeDecrypt(privKey, commonpb.EcPointFormat_UNCOMPRESSED.String(), mEncHelper)
		require.NoError(t, err)

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

func buildRecipientsKeys(t *testing.T, nbOfRecipients int) ([]*hybrid.ECPrivateKey, []*hybrid.ECPublicKey) {
	t.Helper()

	var (
		recipientsPrivKeys []*hybrid.ECPrivateKey
		recipientsPubKeys  []*hybrid.ECPublicKey
	)

	curvProto := commonpb.EllipticCurveType_NIST_P256
	curve, err := hybrid.GetCurve(curvProto.String())
	require.NoError(t, err)

	for i := 0; i < nbOfRecipients; i++ {
		recipientPriv, err := hybrid.GenerateECDHKeyPair(curve)
		require.NoError(t, err)

		recipientsPrivKeys = append(recipientsPrivKeys, recipientPriv)
		recipientsPubKeys = append(recipientsPubKeys, &recipientPriv.PublicKey)
	}

	return recipientsPrivKeys, recipientsPubKeys
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
