/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
)

const (
	defaultHash = crypto.SHA256

	testAlg = "sha-256"
)

func TestGetHash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		digest, err := GetHash(defaultHash, "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0")
		require.NoError(t, err)
		require.Equal(t, "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY", digest)
	})

	t.Run("error - hash not available", func(t *testing.T) {
		digest, err := GetHash(0, "test")
		require.Error(t, err)
		require.Empty(t, digest)
		require.Contains(t, err.Error(), "hash function not available for: 0")
	})
}

func TestParseSDJWT(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		sdJWT := ParseSDJWT(sdJWT)
		require.Equal(t, 1, len(sdJWT.Disclosures))
	})
	t.Run("success", func(t *testing.T) {
		sdJWT := ParseSDJWT(specSDJWT)
		require.Equal(t, 7, len(sdJWT.Disclosures))
	})
}

func TestVerifyDisclosuresInSDJWT(t *testing.T) {
	r := require.New(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signer := afjwt.NewEd25519Signer(privKey)

	t.Run("success", func(t *testing.T) {
		sdJWT := ParseSDJWT(sdJWT)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		signedJWT, err := afjwt.Parse(sdJWT.JWTSerialized, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		err = VerifyDisclosuresInSDJWT(sdJWT.Disclosures, signedJWT)
		r.NoError(err)
	})

	t.Run("success - no selective disclosures(valid case)", func(t *testing.T) {
		payload := &Payload{
			Issuer: "issuer",
			SDAlg:  "sha-256",
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.NoError(err)
	})

	t.Run("success - selective disclosures nil", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = testAlg
		payload["_sd"] = nil

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.NoError(err)
	})

	t.Run("error - disclosure not present in SD-JWT", func(t *testing.T) {
		sdJWT := ParseSDJWT(sdJWT)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		signedJWT, err := afjwt.Parse(sdJWT.JWTSerialized, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		err = VerifyDisclosuresInSDJWT(append(sdJWT.Disclosures, additionalDisclosure), signedJWT)
		r.Error(err)
		r.Contains(err.Error(),
			"disclosure digest 'X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0' not found in SD-JWT disclosure digests")
	})

	t.Run("error - disclosure not present in SD-JWT without selective disclosures", func(t *testing.T) {
		payload := &Payload{
			Issuer: "issuer",
			SDAlg:  testAlg,
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT([]string{additionalDisclosure}, signedJWT)
		r.Error(err)
		r.Contains(err.Error(),
			"disclosure digest 'X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0' not found in SD-JWT disclosure digests")
	})

	t.Run("error - missing algorithm", func(t *testing.T) {
		payload := &Payload{
			Issuer: "issuer",
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg must be present in SD-JWT")
	})

	t.Run("error - invalid algorithm", func(t *testing.T) {
		payload := &Payload{
			Issuer: "issuer",
			SDAlg:  "SHA-XXX",
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg 'SHA-XXX 'not supported")
	})

	t.Run("error - algorithm is not a string", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = 18

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg must be a string")
	})

	t.Run("error - selective disclosures must be an array", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = testAlg
		payload["_sd"] = "test"

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "get disclosure digests: entry type[string] is not an array")
	})

	t.Run("error - selective disclosures must be a string", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = testAlg
		payload["_sd"] = []int{123}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "get disclosure digests: entry item type[float64] is not a string")
	})
}

type NoopSignatureVerifier struct {
}

func (sv *NoopSignatureVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return nil
}

const additionalDisclosure = `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0`

// nolint: lll
const sdJWT = `eyJhbGciOiJFZERTQSJ9.eyJfc2QiOlsicXF2Y3FuY3pBTWdZeDdFeWtJNnd3dHNweXZ5dks3OTBnZTdNQmJRLU51cyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImV4cCI6MTcwMzAyMzg1NSwiaWF0IjoxNjcxNDg3ODU1LCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsIm5iZiI6MTY3MTQ4Nzg1NX0.vscuzfwcHGi04pWtJCadc4iDELug6NH6YK-qxhY1qacsciIHuoLELAfon1tGamHtuu8TSs6OjtLk3lHE16jqAQ~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`

// nolint: lll
const specSDJWT = `eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJfc2QiOiBbIk5ZQ29TUktFWXdYZHBlNXlkdUpYQ3h4aHluRVU4ei1iNFR5TmlhcDc3VVkiLCAiU1k4bjJCYmtYOWxyWTNleEhsU3dQUkZYb0QwOUdGOGE5Q1BPLUc4ajIwOCIsICJUUHNHTlBZQTQ2d21CeGZ2MnpuT0poZmRvTjVZMUdrZXpicGFHWkNUMWFjIiwgIlprU0p4eGVHbHVJZFlCYjdDcWtaYkpWbTB3MlY1VXJSZU5UekFRQ1lCanciLCAibDlxSUo5SlRRd0xHN09MRUlDVEZCVnhtQXJ3OFBqeTY1ZEQ2bXRRVkc1YyIsICJvMVNBc0ozM1lNaW9POXBYNVZlQU0xbHh1SEY2aFpXMmtHZGtLS0JuVmxvIiwgInFxdmNxbmN6QU1nWXg3RXlrSTZ3d3RzcHl2eXZLNzkwZ2U3TUJiUS1OdXMiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNTE2MjM5MDIyLCAiZXhwIjogMTUxNjI0NzAyMiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDhaZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1UW9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkwwRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTRxUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifX19.xqgKrDO6dK_oBL3fiqdcq_elaIGxM6Z-RyuysglGyddR1O1IiE3mIk8kCpoqcRLR88opkVWN2392K_XYfAuAmeT9kJVisD8ZcgNcv-MQlWW9s8WaViXxBRe7EZWkWRQcQVR6jf95XZ5H2-_KA54POq3L42xjk0y5vDr8yc08Reak6vvJVvjXpp-Wk6uxsdEEAKFspt_EYIvISFJhfTuQqyhCjnaW13X312MSQBPwjbHn74ylUqVLljDvqcemxeqjh42KWJq4C3RqNJ7anA2i3FU1kB4-KNZWsijY7-op49iL7BrnIBxdlAMrbHEkoGTbFWdl7Ki17GHtDxxa1jaxQg~WyJkcVR2WE14UzBHYTNEb2FHbmU5eDBRIiwgInN1YiIsICJqb2huX2RvZV80MiJd~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJxUVdtakpsMXMxUjRscWhFTkxScnJ3IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJLVXhTNWhFX1hiVmFjckdBYzdFRnd3IiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyIzcXZWSjFCQURwSERTUzkzOVEtUml3IiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyIweEd6bjNNaXFzY3RaSV9PcERsQWJRIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJFUktNMENOZUZKa2FENW1UWFZfWDh3IiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0`
