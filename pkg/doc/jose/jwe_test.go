/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	exampleJWEAllFields = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
		`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleJWEProtectedFieldAbsent = `{"unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":{"apu":` +
		`"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleCompactJWEAllFields = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DV" +
		"ZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uV" +
		"uxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyP" +
		"GLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKH" +
		"zg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_" +
		"A.XFBoMYUZodetZdvTiFvSkQ"
	exampleJWEUnprotectedFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIs` +
		`InByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","recipients":[{"encrypted_key":"VGVzdEtleQ",` +
		`"header":{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":` +
		`"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleJWERecipientsFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsI` +
		`nByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
		`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{}],"aad":` +
		`"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleJWEAADFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3R` +
		`lZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleJWEIVFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3Rl` +
		`ZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1",` +
		`"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleJWETagFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3R` +
		`lZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotectedtestvalue1"` +
		`,"unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"encrypted_key":"VGVzdEtleQ","header":` +
		`{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","spk":"TestSPK"}}],"aad":"VGVzdEFBRA",` +
		`"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ"}`
	expectedSerializedCompactJWE = `{"protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","unprotected"` +
		`:{},"recipients":[{"encrypted_key":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeips` +
		`EdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_` +
		`lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoR` +
		`dbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","header":{}}],"iv":"48V1_ALb6US0` +
		`4U3b","ciphertext":"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_` +
		`A","tag":"XFBoMYUZodetZdvTiFvSkQ"}`
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
		require.Equal(t, exampleJWEAllFields, serializedJWE)
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
		require.Equal(t, exampleJWEProtectedFieldAbsent, serializedJWE)
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
		require.Equal(t, exampleJWEUnprotectedFieldAbsent, serializedJWE)
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
		require.Equal(t, exampleJWERecipientsFieldAbsent, serializedJWE)
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
		require.Equal(t, exampleJWEIVFieldAbsent, serializedJWE)
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
		require.Equal(t, exampleJWEAADFieldAbsent, serializedJWE)
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
		require.Equal(t, exampleJWETagFieldAbsent, serializedJWE)
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

func TestDeserialize(t *testing.T) {
	t.Run("Full JWE tests", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			deserializedJWE, err := Deserialize(exampleJWEAllFields)
			require.NoError(t, err)
			require.NotNil(t, deserializedJWE)

			reserializedJWE, err := deserializedJWE.Serialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleJWEAllFields, reserializedJWE)
		})
		t.Run("Unable to unmarshal serialized JWE string", func(t *testing.T) {
			deserializedJWE, err := Deserialize("{")
			require.EqualError(t, err, "unexpected end of JSON input")
			require.Nil(t, deserializedJWE)
		})
		t.Run("Protected headers are not base64-encoded", func(t *testing.T) {
			deserializedJWE, err := Deserialize(`{"protected":"Not base64-encoded"}`)
			require.EqualError(t, err, "illegal base64 data at input byte 3")
			require.Nil(t, deserializedJWE)
		})
		t.Run("Protected headers are base64-encoded, but cannot be unmarshalled", func(t *testing.T) {
			deserializedJWE, err := Deserialize(`{"protected":"` +
				base64.RawURLEncoding.EncodeToString([]byte("invalid protected headers")) + `"}`)
			require.EqualError(t, err, "invalid character 'i' looking for beginning of value")
			require.Nil(t, deserializedJWE)
		})
		t.Run("Unable to unmarshal unprotected headers", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0", "unprotected":""}`)
			require.EqualError(t, err, "json: cannot unmarshal string into Go value of type jose.Headers")
			require.Nil(t, deserializedJWE)
		})
		t.Run("Unable to unmarshal recipients", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
					`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":""}`)
			require.EqualError(t, err, "json: cannot unmarshal string into Go value of type []*jose.Recipient")
			require.Nil(t, deserializedJWE)
		})
		t.Run("AAD is not base64-encoded", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
					`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"aad":"not base64-encoded"}`)
			require.EqualError(t, err, "illegal base64 data at input byte 3")
			require.Nil(t, deserializedJWE)
		})
		t.Run("IV is not base64-encoded", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
					`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"iv":"not base64-encoded"}`)
			require.EqualError(t, err, "illegal base64 data at input byte 3")
			require.Nil(t, deserializedJWE)
		})
		t.Run("Ciphertext is not base64-encoded", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
					`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"ciphertext":` +
					`"not base64-encoded"}`)
			require.EqualError(t, err, "illegal base64 data at input byte 3")
			require.Nil(t, deserializedJWE)
		})
		t.Run("Tag is not base64-encoded", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
					`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"tag":"not base64-encoded"}`)
			require.EqualError(t, err, "illegal base64 data at input byte 3")
			require.Nil(t, deserializedJWE)
		})
	})
	t.Run("Flattened JWE tests", func(t *testing.T) {
		t.Run("Recipient encrypted key is not base64-encoded", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
					`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"encrypted_key":` +
					`"not base64-encoded"}`)
			require.EqualError(t, err, "illegal base64 data at input byte 3")
			require.Nil(t, deserializedJWE)
		})
		t.Run("Unable to unmarshal single recipient header", func(t *testing.T) {
			deserializedJWE, err := Deserialize(
				`{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZG` +
					`hlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":` +
					`"unprotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"header":` +
					`"not a valid value"}`)
			require.EqualError(t, err, "invalid character 'o' in literal null (expecting 'u')")
			require.Nil(t, deserializedJWE)
		})
	})
	t.Run("Compact JWE tests", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			deserializedJWE, err := Deserialize(exampleCompactJWEAllFields)
			require.NoError(t, err)
			require.NotNil(t, deserializedJWE)

			reserializedJWE, err := deserializedJWE.Serialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, expectedSerializedCompactJWE, reserializedJWE)
		})
		t.Run("Invalid compact JWE - wrong number of parts", func(t *testing.T) {
			deserializedJWE, err := Deserialize("")
			require.Equal(t, errWrongNumberOfCompactJWEParts, err)
			require.Nil(t, deserializedJWE)
		})
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
