/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	. "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

type attachedData struct {
	Name string
}

func TestGenericAttachment(t *testing.T) {
	t.Run("convert nil slices of attachments", func(t *testing.T) {
		require.Nil(t, V1AttachmentsToGeneric(nil))
		require.Nil(t, V2AttachmentsToGeneric(nil))
		require.Nil(t, GenericAttachmentsToV1(nil))
		require.Nil(t, GenericAttachmentsToV2(nil))
	})

	t.Run("v1 attachments to/from generic", func(t *testing.T) {
		srcAttachments := []Attachment{
			{
				ID: "att-1",
				Data: AttachmentData{
					JSON: attachedData{
						Name: "foo",
					},
				},
			},
			{
				ID: "att-2",
				Data: AttachmentData{
					JSON: attachedData{
						Name: "bar",
					},
				},
			},
			{
				ID: "att-3",
				Data: AttachmentData{
					JSON: attachedData{
						Name: "baz",
					},
				},
			},
		}

		genericAttachments := V1AttachmentsToGeneric(srcAttachments)

		for _, ga := range genericAttachments {
			require.Equal(t, DIDCommV1, ga.Version())
		}

		result := GenericAttachmentsToV1(genericAttachments)

		require.Equal(t, srcAttachments, result)
	})

	t.Run("v2 attachments to/from generic", func(t *testing.T) {
		srcAttachments := []AttachmentV2{
			{
				ID: "att-1",
				Data: AttachmentData{
					JSON: attachedData{
						Name: "foo",
					},
				},
			},
			{
				ID: "att-2",
				Data: AttachmentData{
					JSON: attachedData{
						Name: "bar",
					},
				},
			},
			{
				ID: "att-3",
				Data: AttachmentData{
					JSON: attachedData{
						Name: "baz",
					},
				},
			},
		}

		genericAttachments := V2AttachmentsToGeneric(srcAttachments)

		for _, ga := range genericAttachments {
			require.Equal(t, DIDCommV2, ga.Version())
		}

		result := GenericAttachmentsToV2(genericAttachments)

		require.Equal(t, srcAttachments, result)
	})
}

func TestAttachmentData_Fetch(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		expected := map[string]interface{}{
			"FirstName": "John",
			"LastName":  "Doe",
		}
		bits, err := (&AttachmentData{JSON: expected}).Fetch()
		require.NoError(t, err)
		result := make(map[string]interface{})
		err = json.Unmarshal(bits, &result)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("base64", func(t *testing.T) {
		expected := &testStruct{
			FirstName: "John",
			LastName:  "Doe",
		}
		tmp, err := json.Marshal(expected)
		require.NoError(t, err)
		encoded := base64.StdEncoding.EncodeToString(tmp)
		bytes, err := (&AttachmentData{Base64: encoded}).Fetch()
		require.NoError(t, err)
		result := &testStruct{}
		err = json.Unmarshal(bytes, result)
		require.NoError(t, err)
		require.Equal(t, expected, result)
	})
	t.Run("invalid json", func(t *testing.T) {
		_, err := (&AttachmentData{JSON: func() {}}).Fetch()
		require.Error(t, err)
	})
	t.Run("invalid base64", func(t *testing.T) {
		_, err := (&AttachmentData{Base64: "invalid"}).Fetch()
		require.Error(t, err)
	})
	t.Run("no contents", func(t *testing.T) {
		_, err := (&AttachmentData{}).Fetch()
		require.Error(t, err)
	})
}

type testStruct struct {
	FirstName string
	LastName  string
}

func TestSignVerify(t *testing.T) {
	k := newKMS(t)

	c, err := tinkcrypto.New()
	require.NoError(t, err)

	kid, pubKeyBytes, err := k.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	pubKey := ed25519.PublicKey(pubKeyBytes)

	kh, err := k.Get(kid)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		err = data.Verify(c, k)
		require.NoError(t, err)
	})

	t.Run("success: ecdsa keys", func(t *testing.T) {
		testCases := []struct {
			testName string
			curve    elliptic.Curve
			keyType  kms.KeyType
		}{
			{
				"p256",
				elliptic.P256(),
				kms.ECDSAP256TypeIEEEP1363,
			},
			{
				"p384",
				elliptic.P384(),
				kms.ECDSAP384TypeIEEEP1363,
			},
			{
				"p521",
				elliptic.P521(),
				kms.ECDSAP521TypeIEEEP1363,
			},
		}

		t.Parallel()

		for _, testCase := range testCases {
			t.Run(testCase.testName, func(t *testing.T) {
				priv, err2 := ecdsa.GenerateKey(testCase.curve, rand.Reader)
				require.NoError(t, err2)

				kid2, kh2, err2 := k.ImportPrivateKey(priv, testCase.keyType)
				require.NoError(t, err2)

				pub, err2 := k.ExportPubKeyBytes(kid2)
				require.NoError(t, err2)

				data := mockAttachmentData()

				err2 = data.Sign(c, kh2, &priv.PublicKey, pub)
				require.NoError(t, err2)

				err2 = data.Verify(c, k)
				require.NoError(t, err2)
			})
		}
	})

	t.Run("fail to sign, not given a key handle", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, nil, pubKey, pubKeyBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing data")
	})

	t.Run("fail to sign, invalid pub key type", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, &struct{}{}, pubKeyBytes)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating jwk from pub key")
	})

	t.Run("fail to verify unsigned payload", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no signature")
	})

	t.Run("fail to verify with invalid jws json", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		data.JWS = []byte("{{{{uh oh")

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing jws")
	})

	t.Run("fail to verify with invalid jws kid", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		data.JWS = []byte(`{"header":{"kid":"uh oh"}}`)

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing did:key")
	})

	t.Run("fail to verify with invalid protected header bsae64 data", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		data.JWS = []byte(`{
"header":{"kid":"did:key:z6MksX3A44VzNYx1MJYUddyyZBhbqKUMBqvh37t1onsrBs64"},
"signature":"5cEth8Bwl0PGoMVryOnzTxn6y4zZTccSThLHANz0bxdNr-wS9Y0pPFRASawQyN7i_-XBCRBqAtrRNZZUOqzvCg",
"protected":"#$#$#$ not base64 data"
}`)

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decoding protected header")
	})

	t.Run("fail to verify with invalid protected header json", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		data.JWS = []byte(fmt.Sprintf(`{
"header":{"kid":"did:key:z6MksX3A44VzNYx1MJYUddyyZBhbqKUMBqvh37t1onsrBs64"},
"signature":"5cEth8Bwl0PGoMVryOnzTxn6y4zZTccSThLHANz0bxdNr-wS9Y0pPFRASawQyN7i_-XBCRBqAtrRNZZUOqzvCg",
"protected":"%s"
}`,
			base64.RawURLEncoding.EncodeToString([]byte("#$#$#$ not json data")),
		))

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing protected header")
	})

	t.Run("fail to verify with invalid jwk value", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		data.JWS = []byte(fmt.Sprintf(`{
"header":{"kid":"did:key:z6MksX3A44VzNYx1MJYUddyyZBhbqKUMBqvh37t1onsrBs64"},
"signature":"5cEth8Bwl0PGoMVryOnzTxn6y4zZTccSThLHANz0bxdNr-wS9Y0pPFRASawQyN7i_-XBCRBqAtrRNZZUOqzvCg",
"protected":"%s"
}`,
			base64.RawURLEncoding.EncodeToString(
				[]byte(`{"jwk":"this is not a jwk, this is a string'","alg":"EdDSA"}`)),
		))

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing jwk")
	})

	t.Run("fail to verify with unsupported JWK type", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		data.JWS = []byte(fmt.Sprintf(`{
"header":{"kid":"did:key:z6MksX3A44VzNYx1MJYUddyyZBhbqKUMBqvh37t1onsrBs64"},
"signature":"5cEth8Bwl0PGoMVryOnzTxn6y4zZTccSThLHANz0bxdNr-wS9Y0pPFRASawQyN7i_-XBCRBqAtrRNZZUOqzvCg",
"protected":"%s"
}`,
			base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
				`{"jwk":%s,"alg":"EdDSA"}`,
				`{
			"kty": "RSA",
			"e": "AQAB",
			"use": "enc",
			"kid": "sample@sample.id",
			"alg": "RS256",
			"n": "1hOl09BUnwY7jFBqoZKa4XDmIuc0YFb4y_5ThiHhLRW68aNG5Vo23n3ugND2GK3PsguZqJ_HrWCGVuVlKTmFg`+
					`JWQD9ZnVcYqScgHpQRhxMBi86PIvXR01D_PWXZZjvTRakpvQxUT5bVBdWnaBHQoxDBt0YIVi5a7x-gXB1aDlts4RTMpfS9BPmEjX`+
					`4lciozwS6Ow_wTO3C2YGa_Our0ptIxr-x_3sMbPCN8Fe_iaBDezeDAm39xCNjFa1E735ipXA4eUW_6SzFJ5-bM2UKba2WE6xUaEa5G1`+
					`MDDHCG5LKKd6Mhy7SSAzPOR2FTKYj89ch2asCPlbjHTu8jS6Iy8"
		}`, // not a supported key type
			))),
		))

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting KeyType for jwk")
	})

	validProtectedHeader := `{
"jwk":{"kty":"OKP","kid":"did:key:z6Mkuj5M8J9kce3c4zb33xGTwJdV4h1qH9KWiwoHyziUB2o2","crv":"Ed25519",
"x":"4uyAPkoQrHpL2e4oW2RK_ByoywNBTPPp7C-pltUFkLE"},"alg":"EdDSA"}`

	t.Run("fail to verify with signature not valid raw url base64", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		data.JWS = []byte(fmt.Sprintf(`{
"header":{"kid":"did:key:z6Mkuj5M8J9kce3c4zb33xGTwJdV4h1qH9KWiwoHyziUB2o2"},
"signature":"!@# not a valid raw url base64 encoded value #*$&@*#",
"protected":"%s"
}`,
			base64.RawURLEncoding.EncodeToString([]byte(validProtectedHeader)),
		))

		err = data.Verify(c, k)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decoding signature")
	})

	t.Run("failed to construct pub key handle", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		expected := fmt.Errorf("test error")
		badKMS := &mockkms.KeyManager{PubKeyBytesToHandleErr: expected}

		err = data.Verify(c, badKMS)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("verification uses wrong key", func(t *testing.T) {
		data := mockAttachmentData()

		err = data.Sign(c, kh, pubKey, pubKeyBytes)
		require.NoError(t, err)

		kid, _, err := k.CreateAndExportPubKeyBytes(kms.ED25519)
		require.NoError(t, err)

		kh, err := k.Get(kid)
		require.NoError(t, err)

		badKMS := &mockkms.KeyManager{PubKeyBytesToHandleValue: kh.(*keyset.Handle)}

		err = data.Verify(c, badKMS)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification")
	})
}

func mockAttachmentData() *AttachmentData {
	return &AttachmentData{Base64: base64.RawURLEncoding.EncodeToString([]byte(`lorem ipsum dolor sit amet`))}
}

func newKMS(t *testing.T) kms.KeyManager {
	t.Helper()

	store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}
	sProvider := mockstorage.NewCustomMockStoreProvider(store)

	kmsProv := &protocol.MockProvider{
		StoreProvider: sProvider,
		CustomLock:    &noop.NoLock{},
	}

	customKMS, err := localkms.New("local-lock://primary/test/", kmsProv)
	require.NoError(t, err)

	return customKMS
}
