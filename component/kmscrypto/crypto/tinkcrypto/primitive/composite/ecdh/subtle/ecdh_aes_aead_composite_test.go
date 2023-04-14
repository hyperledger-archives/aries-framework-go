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
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
)

func TestEncryptDecrypt(t *testing.T) {
	aeadPrimitive := getAEADPrimitive(t, aead.AES256GCMKeyTemplate())

	mEncHelper := &MockEncHelper{
		AEADValue:    aeadPrimitive,
		TagSizeValue: subtleaead.AESGCMTagSize,
		IVSizeValue:  subtleaead.AESGCMIVSize,
	}

	cek := random.GetRandomBytes(uint32(32))

	cEnc := NewECDHAEADCompositeEncrypt(mEncHelper, cek)

	pt := []byte("secret message")
	aad := []byte("aad message")

	ct, err := cEnc.Encrypt(pt, aad)
	require.NoError(t, err)

	dEnc := NewECDHAEADCompositeDecrypt(mEncHelper, cek)

	dpt, err := dEnc.Decrypt(ct, aad)
	require.NoError(t, err)
	require.EqualValues(t, pt, dpt)
}

func TestEncryptDecryptNegativeTCs(t *testing.T) {
	aeadPrimitive := getAEADPrimitive(t, aead.AES256GCMKeyTemplate())

	mEncHelper := &MockEncHelper{
		AEADValue:    aeadPrimitive,
		TagSizeValue: subtleaead.AESGCMTagSize,
		IVSizeValue:  subtleaead.AESGCMIVSize,
	}

	pt := []byte("secret message")
	aad := []byte("aad message")
	cek := random.GetRandomBytes(uint32(32))

	// test with GetAEAD() returning error
	mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

	cEnc := NewECDHAEADCompositeEncrypt(mEncHelper, cek)

	// Encrypt should fail with AEAD error value
	_, err := cEnc.Encrypt(pt, aad)
	require.EqualError(t, err, "error from GetAEAD")

	mEncHelper.AEADErrValue = nil

	// Encrypt should fail with nil cek
	cEncNilCEK := NewECDHAEADCompositeEncrypt(mEncHelper, nil)
	_, err = cEncNilCEK.Encrypt(pt, aad)
	require.EqualError(t, err, "ecdhAEADCompositeEncrypt: missing cek")

	// create a valid ciphertext to test Decrypt for all recipients
	cEnc = NewECDHAEADCompositeEncrypt(mEncHelper, cek)

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

	// test with GetAEAD() returning error
	mEncHelper.AEADErrValue = fmt.Errorf("error from GetAEAD")

	dEnc := NewECDHAEADCompositeDecrypt(mEncHelper, cek)

	_, err = dEnc.Decrypt(ct, aad)
	require.EqualError(t, err, "error from GetAEAD")

	mEncHelper.AEADErrValue = nil

	// Decrypt should fail with nil cek
	dEncNilCEK := NewECDHAEADCompositeDecrypt(mEncHelper, nil)
	_, err = dEncNilCEK.Decrypt(ct, aad)
	require.EqualError(t, err, "ecdh decrypt: missing cek")

	// create a valid Decrypt message and test against ct
	dEnc = NewECDHAEADCompositeDecrypt(mEncHelper, cek)

	// try decrypting empty ct
	_, err = dEnc.Decrypt([]byte{}, aad)
	require.EqualError(t, err, "unexpected end of JSON input")

	// finally try successful decrypt
	dpt, err := dEnc.Decrypt(ct, aad)
	require.NoError(t, err)
	require.EqualValues(t, pt, dpt)
}

func TestEncryptDecryptWithSingleRecipient(t *testing.T) {
	aeadPrimitive := getAEADPrimitive(t, aead.AES256GCMKeyTemplate())

	mEncHelper := &MockEncHelper{
		AEADValue:    aeadPrimitive,
		TagSizeValue: subtleaead.AESGCMTagSize,
		IVSizeValue:  subtleaead.AESGCMIVSize,
	}

	pt := []byte("secret message")
	cek := random.GetRandomBytes(uint32(32))
	cEnc := NewECDHAEADCompositeEncrypt(mEncHelper, cek)
	newAAD := base64.RawURLEncoding.EncodeToString([]byte("{\"enc\":\"testAlg\"}"))

	// Encrypt should pass with base64Url encoded a valid json marshaled aad
	ct, err := cEnc.Encrypt(pt, []byte(newAAD))
	require.NoError(t, err)

	encData := &composite.EncryptedData{}
	err = json.Unmarshal(ct, encData)
	require.NoError(t, err)

	dEnc := NewECDHAEADCompositeDecrypt(mEncHelper, cek)

	dpt, err := dEnc.Decrypt(ct, []byte(newAAD))
	require.NoError(t, err)
	require.EqualValues(t, pt, dpt)
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
	AEADValue    tink.AEAD
	AEADErrValue error
	TagSizeValue int
	IVSizeValue  int
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
func (m *MockEncHelper) BuildEncData(ct []byte) ([]byte, error) {
	tagSize := m.GetTagSize()
	ivSize := m.GetIVSize()
	iv := ct[:ivSize]
	ctAndTag := ct[ivSize:]
	tagOffset := len(ctAndTag) - tagSize

	encData := &composite.EncryptedData{
		Ciphertext: ctAndTag[:tagOffset],
		IV:         iv,
		Tag:        ctAndTag[tagOffset:],
	}

	return json.Marshal(encData)
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
