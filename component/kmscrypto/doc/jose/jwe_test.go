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

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
)

const (
	exampleEPK = `{"kty":"EC","crv":"P-256","x":"0_Zip_vHBNI-P_in4S2OuPsxWy9cMWCem-ubr4hK1D0","y":"UTIlc5Vf0Ul` +
		`yrOgxFzZjt3JwKTA99cfkVNGu70_UZpA"}`

	exampleMockJWEAllFields = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVl` +
		`MSIsInByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unp` +
		`rotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"header":{"apu":"Tes` +
		`tAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"encrypted_key":"VGVzdE` +
		`tleQ"},{"header":{"apu":"TestAPU2","iv":"TestIV2","tag":"TestTag2","kid":"TestKID2","epk":` +
		exampleEPK + `},"encrypt` + `ed_key":"VGVzdEtleTI"}],"aad":"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"` +
		`VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleMockJWEAllFieldsOneRecipient = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVl` +
		`MSIsInByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unp` +
		`rotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"encrypted_key":"VGVzdEtleQ","heade` +
		`r":{"apu":"TestAPU","iv":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"aad":"VG` +
		`VzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleMockJWEProtectedFieldAbsent = `{"unprotected":{"unprotectedheader1":"unprotectedtestvalue1","unpr` +
		`otectedheader2":"unprotectedtestvalue2"},"recipients":[{"header":{"apu":"TestAPU","iv":"TestIV","tag"` +
		`:"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"encrypted_key":"VGVzdEtleQ"},{"header":{"apu":"` +
		`TestAPU2","iv":"TestIV2","tag":"TestTag2","kid":"TestKID2","epk":` + exampleEPK + `},"encrypted_key":` +
		`"VGVzdEtleTI"}],"aad":"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleMockJWEUnprotectedFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVl` +
		`MSIsInByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","recipients":[{"header":{"apu":"TestAPU"` +
		`,"iv":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"encrypted_key":"VGVzdEtleQ"` +
		`},{"header":{"apu":"TestAPU2","iv":"TestIV2","tag":"TestTag2","kid":"TestKID2","epk":` + exampleEPK +
		`},"encrypted_key":"VGVzdEtleTI"}],"aad":"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleH` +
		`Q","tag":"VGVzdFRhZw"}`
	exampleMockJWERecipientsFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVl` +
		`MSIsInByb3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unp` +
		`rotectedtestvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{}],"aad":"VGVzdEFBRA` +
		`","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleMockJWEIVFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInBy` +
		`b3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotected` +
		`testvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"header":{"apu":"TestAPU","i` +
		`v":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"encrypted_key":"VGVzdEtleQ"},{` +
		`"header":{"apu":"TestAPU2","iv":"TestIV2","tag":"TestTag2","kid":"TestKID2","epk":` + exampleEPK + `}` +
		`,"encrypted_key":"VGVzdEtleTI"}],"aad":"VGVzdEFBRA","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleMockJWEAADFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInBy` +
		`b3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotected` +
		`testvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"header":{"apu":"TestAPU","i` +
		`v":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"encrypted_key":"VGVzdEtleQ"},{` +
		`"header":{"apu":"TestAPU2","iv":"TestIV2","tag":"TestTag2","kid":"TestKID2","epk":` + exampleEPK + `}` +
		`,"encrypted_key":"VGVzdEtleTI"}],"iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ","tag":"VGVzdFRhZw"}`
	exampleMockJWETagFieldAbsent = `{"protected":"eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInBy` +
		`b3RlY3RlZGhlYWRlcjIiOiJwcm90ZWN0ZWR0ZXN0dmFsdWUyIn0","unprotected":{"unprotectedheader1":"unprotected` +
		`testvalue1","unprotectedheader2":"unprotectedtestvalue2"},"recipients":[{"header":{"apu":"TestAPU","i` +
		`v":"TestIV","tag":"TestTag","kid":"TestKID","epk":` + exampleEPK + `},"encrypted_key":"VGVzdEtleQ"},{` +
		`"header":{"apu":"TestAPU2","iv":"TestIV2","tag":"TestTag2","kid":"TestKID2","epk":` + exampleEPK + `}` +
		`,"encrypted_key":"VGVzdEtleTI"}],"aad":"VGVzdEFBRA","iv":"VGVzdElW","ciphertext":"VGVzdENpcGhlclRleHQ"}`

	exampleRealFullJWE = `{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://serv` +
		`er.example.com/keys.jwks"},"recipients":[{"header":{"alg":"RSA1_5","kid":"2011-04-29"},"encrypted_key` +
		`":"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdU` +
		`LU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU` +
		`7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP` +
		`-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"},{"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6K` +
		`B707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}],"iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"K` +
		`DlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}`
	exampleRealFullJWEWithEPKs = `{"protected":"eyJlbmMiOiJBMjU2R0NNIn0","recipients":[{"header":{"alg":"ECDH-` +
		`ES+A256KW","epk":{"kty":"EC","crv":"P-256","x":"nHdqtsfXMabc2a1dtpnOgvWhkRiPxHopnfFH-BtSOaQ","y":"GWG` +
		`uLnoohFrpXExSuuuOz-p3uSFFq1FVZP0dN-3q9H8"}},"encrypted_key":"fE26rjeON_iBo84fkvD56nLthhRM04LPzrYiIUQ4` +
		`E5caOhtU95-t2w"},{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"EC","crv":"P-256","x":"r2wTh-URkmIuK` +
		`3f4LaJvPP7wTZVG7sdVatGxGadPPqA","y":"tZ29KzMcIrF9j-SakwtR9a-qP0iV4hdaeghjnpPgoaQ"}},"encrypted_key":"` +
		`cixwgiJZK3JtKAOX2UHSE9N_4s4CXruAWby8efyQWueY-wx0_qeIrg"},{"header":{"alg":"ECDH-ES+A256KW","epk":{"kt` +
		`y":"EC","crv":"P-256","x":"t0p3XILJf-1FMkuQqyX59kBpxVaYd-DIjrY3oDxvFHA","y":"Wfme-7LxEUK7sewvXhxrTV6c` +
		`EVMkROPGbd2glkddAZs"}},"encrypted_key":"YSQvknAFf5teYWg2eciNiVx5oXNbKS688Dd_0aVxgtFtelxqc8Jv0g"}],"iv` +
		`":"8-9HnO8n5et1Se3y","ciphertext":"jlgZfA44GMe-mhZLzxcur9g40g","tag":"rbXD5g7QxIOc4_J7idRHQA"}`
	exampleRealCompactJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DV" +
		"ZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uV" +
		"uxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyP" +
		"GLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKH" +
		"zg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_" +
		"A.XFBoMYUZodetZdvTiFvSkQ"

	expectedSerializedCompactJWE = `{"protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_k` +
		`ey":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKA` +
		`q7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfw` +
		`X7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWX` +
		`RcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","iv":"48V1_ALb6US04U3b","ciphertext":"5eym8TW_c8SuK0ltJ` +
		`3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","tag":"XFBoMYUZodetZdvTiFvSkQ"}`

	expectedCompactJWE = `eyJwcm90ZWN0ZWRoZWFkZXIxIjoicHJvdGVjdGVkdGVzdHZhbHVlMSIsInByb3RlY3RlZGhlYWRlcjIiOiJw` +
		`cm90ZWN0ZWR0ZXN0dmFsdWUyIn0.VGVzdEtleQ.VGVzdElW.VGVzdENpcGhlclRleHQ.VGVzdFRhZw`
)

var errFailingMarshal = errors.New("i failed to marshal")

func TestJSONWebEncryption_Serialize(t *testing.T) {
	t.Run("Success cases", func(t *testing.T) {
		t.Run("All fields filled, multiple recipients", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}
			recipients := make([]*Recipient, 2)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}
			recipients[1] = &Recipient{
				EncryptedKey: "TestKey2",
				Header: &RecipientHeaders{
					APU: "TestAPU2",
					IV:  "TestIV2",
					Tag: "TestTag2",
					KID: "TestKID2",
					EPK: []byte(exampleEPK),
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
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEAllFields, serializedJWE)
		})
		t.Run("All fields filled, one recipient - serialized JWE uses flattened syntax", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}
			recipients := make([]*Recipient, 1)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
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
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEAllFieldsOneRecipient, serializedJWE)
		})
		t.Run("Successfully serialize JWE, protected header value is empty", func(t *testing.T) {
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}
			recipients := make([]*Recipient, 2)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}
			recipients[1] = &Recipient{
				EncryptedKey: "TestKey2",
				Header: &RecipientHeaders{
					APU: "TestAPU2",
					IV:  "TestIV2",
					Tag: "TestTag2",
					KID: "TestKID2",
					EPK: []byte(exampleEPK),
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
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEProtectedFieldAbsent, serializedJWE)
		})
		t.Run("Successfully serialize JWE, unprotected header value is empty", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			recipients := make([]*Recipient, 2)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}
			recipients[1] = &Recipient{
				EncryptedKey: "TestKey2",
				Header: &RecipientHeaders{
					APU: "TestAPU2",
					IV:  "TestIV2",
					Tag: "TestTag2",
					KID: "TestKID2",
					EPK: []byte(exampleEPK),
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
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEUnprotectedFieldAbsent, serializedJWE)
		})
		t.Run("Successfully serialize JWE, recipients value is empty", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}

			jwe := JSONWebEncryption{
				ProtectedHeaders:   protectedHeaders,
				UnprotectedHeaders: unprotectedHeaders,
				AAD:                "TestAAD",
				IV:                 "TestIV",
				Ciphertext:         "TestCipherText",
				Tag:                "TestTag",
			}
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWERecipientsFieldAbsent, serializedJWE)
		})
		t.Run("Successfully serialize JWE, IV value is empty", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}
			recipients := make([]*Recipient, 2)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}
			recipients[1] = &Recipient{
				EncryptedKey: "TestKey2",
				Header: &RecipientHeaders{
					APU: "TestAPU2",
					IV:  "TestIV2",
					Tag: "TestTag2",
					KID: "TestKID2",
					EPK: []byte(exampleEPK),
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
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			println(serializedJWE)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEIVFieldAbsent, serializedJWE)
		})
		t.Run("Successfully serialize JWE, AAD value is empty", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}
			recipients := make([]*Recipient, 2)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}
			recipients[1] = &Recipient{
				EncryptedKey: "TestKey2",
				Header: &RecipientHeaders{
					APU: "TestAPU2",
					IV:  "TestIV2",
					Tag: "TestTag2",
					KID: "TestKID2",
					EPK: []byte(exampleEPK),
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
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEAADFieldAbsent, serializedJWE)
		})
		t.Run("Successfully serialize JWE, tag value is empty", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}
			recipients := make([]*Recipient, 2)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header: &RecipientHeaders{
					APU: "TestAPU",
					IV:  "TestIV",
					Tag: "TestTag",
					KID: "TestKID",
					EPK: []byte(exampleEPK),
				},
			}
			recipients[1] = &Recipient{
				EncryptedKey: "TestKey2",
				Header: &RecipientHeaders{
					APU: "TestAPU2",
					IV:  "TestIV2",
					Tag: "TestTag2",
					KID: "TestKID2",
					EPK: []byte(exampleEPK),
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
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWETagFieldAbsent, serializedJWE)
		})
	})
	t.Run("Error cases", func(t *testing.T) {
		t.Run("Fail to serialize JWE, ciphertext value is empty", func(t *testing.T) {
			protectedHeaders := Headers{
				"protectedheader1": "protectedtestvalue1",
				"protectedheader2": "protectedtestvalue2",
			}
			unprotectedHeaders := Headers{
				"unprotectedheader1": "unprotectedtestvalue1",
				"unprotectedheader2": "unprotectedtestvalue2",
			}

			jwe := JSONWebEncryption{
				ProtectedHeaders:   protectedHeaders,
				UnprotectedHeaders: unprotectedHeaders,
				Recipients:         nil,
				AAD:                "TestAAD",
				IV:                 "TestIV",
				Tag:                "TestTag",
			}
			serializedJWE, err := jwe.FullSerialize(json.Marshal)
			require.Equal(t, errEmptyCiphertext, err)
			require.Equal(t, "", serializedJWE)
		})
		t.Run("fail to prepare headers", func(t *testing.T) {
			jwe := JSONWebEncryption{
				ProtectedHeaders: Headers{},
			}

			fm := &failingMarshaller{
				numTimesMarshalCalledBeforeReturnErr: 0,
			}

			serializedJWE, err := jwe.FullSerialize(fm.failingMarshal)
			require.Equal(t, errFailingMarshal, err)
			require.Empty(t, serializedJWE)
		})
		t.Run("Fail to marshal recipient header (single recipient)", func(t *testing.T) {
			recipients := make([]*Recipient, 1)

			recipients[0] = &Recipient{
				EncryptedKey: "TestKey",
				Header:       &RecipientHeaders{},
			}

			jwe := JSONWebEncryption{
				Recipients: recipients,
			}

			fm := &failingMarshaller{
				numTimesMarshalCalledBeforeReturnErr: 0,
			}

			serializedJWE, err := jwe.FullSerialize(fm.failingMarshal)
			require.Equal(t, errFailingMarshal, err)
			require.Empty(t, serializedJWE)
		})
		t.Run("fail to marshal recipients", func(t *testing.T) {
			jwe := JSONWebEncryption{
				Recipients: make([]*Recipient, 2),
			}

			jwe.Recipients[0] = &Recipient{}
			jwe.Recipients[1] = &Recipient{}

			fm := &failingMarshaller{
				numTimesMarshalCalledBeforeReturnErr: 0,
			}

			serializedJWE, err := jwe.FullSerialize(fm.failingMarshal)
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

			serializedJWE, err := jwe.FullSerialize(fm.failingMarshal)
			require.Equal(t, errFailingMarshal, err)
			require.Empty(t, serializedJWE)
		})
	})
}

func TestJSONWebEncryption_CompactSerialize(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		protectedHeaders := Headers{
			"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2",
		}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders: protectedHeaders,
			Recipients:       recipients,
			IV:               "TestIV",
			Ciphertext:       "TestCipherText",
			Tag:              "TestTag",
		}

		compactJWE, err := jwe.CompactSerialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, expectedCompactJWE, compactJWE)
	})
	t.Run("Unable to compact serialize - missing protected headers", func(t *testing.T) {
		jwe := JSONWebEncryption{}

		compactJWE, err := jwe.CompactSerialize(json.Marshal)
		require.Equal(t, errProtectedHeaderMissing, err)
		require.Empty(t, compactJWE)
	})
	t.Run("Unable to compact serialize - too many recipients", func(t *testing.T) {
		protectedHeaders := Headers{
			"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2",
		}
		recipients := make([]*Recipient, 2)

		jwe := JSONWebEncryption{
			ProtectedHeaders: protectedHeaders,
			Recipients:       recipients,
		}

		compactJWE, err := jwe.CompactSerialize(json.Marshal)
		require.Equal(t, errNotOnlyOneRecipient, err)
		require.Empty(t, compactJWE)
	})
	t.Run("Unable to compact serialize - JWE contains an unprotected header", func(t *testing.T) {
		protectedHeaders := Headers{
			"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2",
		}
		unprotectedHeaders := Headers{
			"unprotectedheader1": "unprotectedtestvalue1",
			"unprotectedheader2": "unprotectedtestvalue2",
		}
		recipients := make([]*Recipient, 1)

		jwe := JSONWebEncryption{
			ProtectedHeaders:   protectedHeaders,
			UnprotectedHeaders: unprotectedHeaders,
			Recipients:         recipients,
			AAD:                "TestAAD",
			IV:                 "TestIV",
			Ciphertext:         "TestCipherText",
			Tag:                "TestTag",
		}

		compactJWE, err := jwe.CompactSerialize(json.Marshal)
		require.Equal(t, errUnprotectedHeaderUnsupported, err)
		require.Empty(t, compactJWE)
	})
	t.Run("Unable to compact serialize - recipient contains a header", func(t *testing.T) {
		protectedHeaders := Headers{
			"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2",
		}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{

			EncryptedKey: "TestKey",
			Header: &RecipientHeaders{
				APU: "TestAPU",
				IV:  "TestIV",
				Tag: "TestTag",
				KID: "TestKID",
				EPK: []byte(exampleEPK),
			},
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders: protectedHeaders,
			Recipients:       recipients,
		}

		compactJWE, err := jwe.CompactSerialize(json.Marshal)
		require.Equal(t, errPerRecipientHeaderUnsupported, err)
		require.Empty(t, compactJWE)
	})
	t.Run("Fail to marshal protected headers", func(t *testing.T) {
		protectedHeaders := Headers{
			"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2",
		}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders: protectedHeaders,
			Recipients:       recipients,
			IV:               "TestIV",
			Ciphertext:       "TestCipherText",
			Tag:              "TestTag",
		}

		fm := &failingMarshaller{
			numTimesMarshalCalledBeforeReturnErr: 0,
		}

		compactJWE, err := jwe.CompactSerialize(fm.failingMarshal)
		require.Equal(t, errFailingMarshal, err)
		require.Empty(t, compactJWE)
	})
	t.Run("Fail to marshal with non empty AAD", func(t *testing.T) {
		protectedHeaders := Headers{
			"protectedheader1": "protectedtestvalue1",
			"protectedheader2": "protectedtestvalue2",
		}
		recipients := make([]*Recipient, 1)

		recipients[0] = &Recipient{
			EncryptedKey: "TestKey",
		}

		jwe := JSONWebEncryption{
			ProtectedHeaders: protectedHeaders,
			Recipients:       recipients,
			AAD:              "AAD", // compact serialize should fail with AAD field
			IV:               "TestIV",
			Ciphertext:       "TestCipherText",
			Tag:              "TestTag",
		}

		compactJWE, err := jwe.CompactSerialize(json.Marshal)
		require.EqualError(t, err, errAADHeaderUnsupported.Error())
		require.Empty(t, compactJWE)
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
		t.Run("Success - JWE without EPK", func(t *testing.T) {
			deserializedJWE, err := Deserialize(exampleMockJWEAllFields)
			require.NoError(t, err)
			require.NotNil(t, deserializedJWE)

			reserializedJWE, err := deserializedJWE.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleMockJWEAllFields, reserializedJWE)
		})
		t.Run("Success - JWE with many recipients, each with an EPK", func(t *testing.T) {
			deserializedJWE, err := Deserialize(exampleRealFullJWEWithEPKs)
			require.NoError(t, err)
			require.NotNil(t, deserializedJWE)

			reserializedJWE, err := deserializedJWE.FullSerialize(json.Marshal)
			require.NoError(t, err)
			require.Equal(t, exampleRealFullJWEWithEPKs, reserializedJWE)
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
			require.EqualError(t, err, "json: cannot unmarshal string into Go value of type jose.RecipientHeaders")
			require.Nil(t, deserializedJWE)
		})
	})
	t.Run("Compact JWE tests", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			deserializedJWE, err := Deserialize(exampleRealCompactJWE)
			require.NoError(t, err)
			require.NotNil(t, deserializedJWE)

			reserializedJWE, err := deserializedJWE.FullSerialize(json.Marshal)
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

func TestInterop(t *testing.T) {
	t.Run("Use go-jose to deserialize JWE that's been serialized with Aries", func(t *testing.T) {
		ariesJWE, err := Deserialize(exampleRealFullJWE)
		require.NoError(t, err)
		require.NotNil(t, ariesJWE)

		reserializedAriesJWE, err := ariesJWE.FullSerialize(json.Marshal)
		require.NoError(t, err)
		require.NotEmpty(t, reserializedAriesJWE)

		goJoseJWE, err := jose.ParseEncrypted(reserializedAriesJWE)
		require.NoError(t, err)
		require.NotNil(t, goJoseJWE)
	})
	t.Run("Use go-jose to deserialize JWE that's been compact serialized with Aries", func(t *testing.T) {
		ariesJWE, err := Deserialize(exampleRealCompactJWE)
		require.NoError(t, err)
		require.NotNil(t, ariesJWE)

		compactAriesJWE, err := ariesJWE.CompactSerialize(json.Marshal)
		require.NoError(t, err)
		require.Equal(t, exampleRealCompactJWE, compactAriesJWE)

		goJoseJWE, err := jose.ParseEncrypted(compactAriesJWE)
		require.NoError(t, err)
		require.NotNil(t, goJoseJWE)
	})
	t.Run("Use Aries to deserialize JWE that's been serialized with go-jose using full syntax",
		func(t *testing.T) {
			goJoseJWE, err := jose.ParseEncrypted(exampleRealFullJWE)
			require.NoError(t, err)
			require.NotNil(t, goJoseJWE)

			reserializedGoJoseJWEString := goJoseJWE.FullSerialize()
			require.NotEmpty(t, reserializedGoJoseJWEString)

			ariesJWE, err := Deserialize(reserializedGoJoseJWEString)
			require.NoError(t, err)
			require.NotNil(t, ariesJWE)
		})
	t.Run("Use Aries to deserialize JWE that's been serialized with go-jose using compact syntax",
		func(t *testing.T) {
			goJoseJWE, err := jose.ParseEncrypted(exampleRealCompactJWE)
			require.NoError(t, err)
			require.NotNil(t, goJoseJWE)

			reserializedGoJoseJWEString, err := goJoseJWE.CompactSerialize()
			require.NoError(t, err)
			require.NotEmpty(t, reserializedGoJoseJWEString)

			ariesJWE, err := Deserialize(reserializedGoJoseJWEString)
			require.NoError(t, err)
			require.NotNil(t, ariesJWE)
		})
	t.Run("Deserialize full JWE with aries and go-jose, then reserialize and compare", func(t *testing.T) {
		ariesJWE, err := Deserialize(exampleRealFullJWE)
		require.NoError(t, err)
		require.NotNil(t, ariesJWE)

		reserializedAriesJWE, err := ariesJWE.FullSerialize(json.Marshal)
		require.NoError(t, err)
		require.NotEmpty(t, reserializedAriesJWE)

		require.Equal(t, exampleRealFullJWE, reserializedAriesJWE)

		goJoseJWE, err := jose.ParseEncrypted(exampleRealFullJWE)
		require.NoError(t, err)
		require.NotNil(t, goJoseJWE)

		reserializedGoJoseJWE := goJoseJWE.FullSerialize()
		require.NotEmpty(t, reserializedGoJoseJWE)

		checkEquality(t, reserializedGoJoseJWE, reserializedAriesJWE)
	})
	t.Run("Deserialize compact JWE with aries and go-jose, then reserialize and compare", func(t *testing.T) {
		ariesJWE, err := Deserialize(exampleRealCompactJWE)
		require.NoError(t, err)
		require.NotNil(t, ariesJWE)

		reserializedAriesJWE, err := ariesJWE.FullSerialize(json.Marshal)
		require.NoError(t, err)
		require.NotEmpty(t, reserializedAriesJWE)

		goJoseJWE, err := jose.ParseEncrypted(exampleRealCompactJWE)
		require.NoError(t, err)
		require.NotNil(t, goJoseJWE)

		reserializedGoJoseJWEString := goJoseJWE.FullSerialize()
		require.NotEmpty(t, reserializedGoJoseJWEString)

		require.Equal(t, reserializedGoJoseJWEString, reserializedAriesJWE)
	})
}

func checkEquality(t *testing.T, goJoseJWE, ariesJWE string) {
	// When there are multiple recipients, for some reason the go-jose library seems to put the first recipient's
	// encrypted key in the top-level JSON object - but this should only be done when using the flattened syntax,
	// and that is only allowed when there is a single recipient, so go-jose's serialize function doesn't seem to be
	// strictly compliant with the spec. In order to make the resulting serialized strings comparable,
	// the extra encrypted key field is stripped out.
	goJoseJWEBeforeNonCompliantPart := goJoseJWE[:642]
	gojoseJWEAfterNonCompliantPart := goJoseJWE[1003:]
	goJoseJWEWithoutNonCompliantPart := goJoseJWEBeforeNonCompliantPart + gojoseJWEAfterNonCompliantPart

	require.Equal(t, goJoseJWEWithoutNonCompliantPart, ariesJWE)
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
