/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	expectedJWEAllFields = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
		`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	expectedJWEProtectedFieldAbsent = `{"unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":{"apu":` +
		`"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	expectedJWEUnprotectedFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIs` +
		`InByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","recipients":[{"encrypted_key":"VGVzdEtleQ",` +
		`"header":{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":` +
		`"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	expectedJWERecipientsFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsI` +
		`nByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
		`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{}],"aad":` +
		`"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	expectedJWEAADFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3R` +
		`lZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	expectedJWEIVFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3Rl` +
		`ZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	expectedJWETagFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3R` +
		`lZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1"` +
		`,"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ"}`
)

var errFailingMarshal = errors.New("i failed to marshal")

func TestJSONWebEncryption_Serialize(t *testing.T) {
	t.Run("Successfully serialize JWE, all fields filled", func(t *testing.T) {
		protectedHeaders := Headers{"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2"}
		unprotectedHeaders := Headers{"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2"}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
			Header: RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				SPK: "TestSPK",
			},
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders:   protectedHeaders,
			UnprotectedHeaders: unprotectedHeaders,
			Recipients:         recipients,
			AAD:                "TestAAD",
			IV:                 "TestIV",
			Ciphertext:         "TestCipherText",
			Tag:                "TestTag",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedJWEAllFields, serializedJWE)
	})
	t.Run("Successfully serialize JWE, protected header value is empty", func(t *testing.T) {
		unprotectedHeaders := Headers{"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2"}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
			Header: RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				SPK: "TestSPK",
			},
		}

		jwe := JSONWebEncryption{
			UnprotectedHeaders: unprotectedHeaders,
			Recipients:         recipients,
			AAD:                "TestAAD",
			IV:                 "TestIV",
			Ciphertext:         "TestCipherText",
			Tag:                "TestTag",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedJWEProtectedFieldAbsent, serializedJWE)
	})
	t.Run("Successfully serialize JWE, unprotected header value is empty", func(t *testing.T) {
		protectedHeaders := Headers{"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2"}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
			Header: RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				SPK: "TestSPK",
			},
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders: protectedHeaders,
			Recipients:       recipients,
			AAD:              "TestAAD",
			IV:               "TestIV",
			Ciphertext:       "TestCipherText",
			Tag:              "TestTag",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedJWEUnprotectedFieldAbsent, serializedJWE)
	})
	t.Run("Successfully serialize JWE, recipients value is empty", func(t *testing.T) {
		protectedHeaders := Headers{"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2"}
		unprotectedHeaders := Headers{"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2"}

		jwe := JSONWebEncryption{
			ProtectedHeaders:   protectedHeaders,
			UnprotectedHeaders: unprotectedHeaders,
			AAD:                "TestAAD",
			IV:                 "TestIV",
			Ciphertext:         "TestCipherText",
			Tag:                "TestTag",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedJWERecipientsFieldAbsent, serializedJWE)
	})
	t.Run("Successfully serialize JWE, IV value is empty", func(t *testing.T) {
		protectedHeaders := Headers{"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2"}
		unprotectedHeaders := Headers{"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2"}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
			Header: RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				SPK: "TestSPK",
			},
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders:   protectedHeaders,
			UnprotectedHeaders: unprotectedHeaders,
			Recipients:         recipients,
			AAD:                "TestAAD",
			Ciphertext:         "TestCipherText",
			Tag:                "TestTag",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedJWEIVFieldAbsent, serializedJWE)
	})
	t.Run("Successfully serialize JWE, AAD value is empty", func(t *testing.T) {
		protectedHeaders := Headers{"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2"}
		unprotectedHeaders := Headers{"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2"}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
			Header: RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				SPK: "TestSPK",
			},
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders:   protectedHeaders,
			UnprotectedHeaders: unprotectedHeaders,
			Recipients:         recipients,
			IV:                 "TestIV",
			Ciphertext:         "TestCipherText",
			Tag:                "TestTag",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedJWEAADFieldAbsent, serializedJWE)
	})
	t.Run("Fail to serialize JWE, ciphertext value is empty", func(t *testing.T) {
		protectedHeaders := Headers{"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2"}
		unprotectedHeaders := Headers{"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2"}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
			Header: RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				SPK: "TestSPK",
			},
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders:   protectedHeaders,
			UnprotectedHeaders: unprotectedHeaders,
			Recipients:         recipients,
			AAD:                "TestAAD",
			IV:                 "TestIV",
			Tag:                "TestTag",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.Equal(t, errEmptyCiphertext, err)
		require.Equal(t, "", serializedJWE)
	})
	t.Run("Successfully serialize JWE, tag value is empty", func(t *testing.T) {
		protectedHeaders := Headers{"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2"}
		unprotectedHeaders := Headers{"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2"}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
			Header: RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				SPK: "TestSPK",
			},
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders:   protectedHeaders,
			UnprotectedHeaders: unprotectedHeaders,
			Recipients:         recipients,
			AAD:                "TestAAD",
			IV:                 "TestIV",
			Ciphertext:         "TestCipherText",
		}
		serializedJWE, err := jwe.Serialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedJWETagFieldAbsent, serializedJWE)
	})
	t.Run("fail to prepare headers", func(t *testing.T) {
		jwe := JSONWebEncryption{
			ProtectedHeaders: Headers{},
		}

		fm := &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 0,
		}

		serializedJWE, err := jwe.Serialize(fm.failingMarshal)
		require.Equal(t, errFailingMarshal, err)
		require.Empty(t, serializedJWE)
	})
	t.Run("fail to marshal recipients", func(t *testing.T) {
		jwe := JSONWebEncryption{
			Recipients: make([]*Recipient, 0),
		}

		fm := &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 0,
		}

		serializedJWE, err := jwe.Serialize(fm.failingMarshal)
		require.Equal(t, errFailingMarshal, err)
		require.Empty(t, serializedJWE)
	})
	t.Run("fail to marshal rawJSONWebEncryption", func(t *testing.T) {
		jwe := JSONWebEncryption{
			Ciphertext: "some ciphertext",
		}

		fm := &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 0,
		}

		serializedJWE, err := jwe.Serialize(fm.failingMarshal)
		require.Equal(t, errFailingMarshal, err)
		require.Empty(t, serializedJWE)
	})
}

func TestJSONWebEncryption_PrepareHeaders(t *testing.T) {
	t.Run("fail when marshalling protected headers", func(t *testing.T) {
		jwe := JSONWebEncryption{
			ProtectedHeaders: Headers{},
		}

		fm := &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 0,
		}

		marshalledProtectedHeaders, marshalledUnprotectedHeaders, err :=
			jwe.prepareHeaders(fm.failingMarshal)
		require.Equal(t, errFailingMarshal, err)
		require.Empty(t, marshalledProtectedHeaders)
		require.Nil(t, marshalledUnprotectedHeaders)
	})
	t.Run("fail when marshalling unprotected headers", func(t *testing.T) {
		jwe := JSONWebEncryption{
			ProtectedHeaders:   Headers{},
			UnprotectedHeaders: Headers{},
		}

		fm := &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 1,
		}

		marshalledProtectedHeaders, marshalledUnprotectedHeaders, err :=
			jwe.prepareHeaders(fm.failingMarshal)
		require.Equal(t, errFailingMarshal, err)
		require.Empty(t, marshalledProtectedHeaders)
		require.Nil(t, marshalledUnprotectedHeaders)
	})
}

type failingMarshaller struct {
	numTimesMarshalCalled                int
	numTimesMarshalCalledBeforeReturnErr int
}

func (m *failingMarshaller) failingMarshal(v interface{}) ([]byte, error) {
	if m.numTimesMarshalCalled == m.numTimesMarshalCalledBeforeReturnErr {
		return nil, errFailingMarshal
	}

	m.numTimesMarshalCalled++

	return nil, nil
}
