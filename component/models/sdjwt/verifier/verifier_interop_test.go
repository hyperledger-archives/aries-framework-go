/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/holder"
)

const specIssuanceExample1SDJWTV2 = `eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIk5ZQ29TUktFWXdYZHBlNXlkdUpYQ3h4aHluRVU4ei1iNFR5TmlhcDc3VVkiLCAiU1k4bjJCYmtYOWxyWTNleEhsU3dQUkZYb0QwOUdGOGE5Q1BPLUc4ajIwOCIsICJUUHNHTlBZQTQ2d21CeGZ2MnpuT0poZmRvTjVZMUdrZXpicGFHWkNUMWFjIiwgIlprU0p4eGVHbHVJZFlCYjdDcWtaYkpWbTB3MlY1VXJSZU5UekFRQ1lCanciLCAibDlxSUo5SlRRd0xHN09MRUlDVEZCVnhtQXJ3OFBqeTY1ZEQ2bXRRVkc1YyIsICJvMVNBc0ozM1lNaW9POXBYNVZlQU0xbHh1SEY2aFpXMmtHZGtLS0JuVmxvIiwgInFxdmNxbmN6QU1nWXg3RXlrSTZ3d3RzcHl2eXZLNzkwZ2U3TUJiUS1OdXMiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNTE2MjM5MDIyLCAiZXhwIjogMTUxNjI0NzAyMiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.gieinY5mTgTV69KZJyaFPeIJ9tfXlzCHKfs-HMBO9UIREz6Dh_lpTMrwUUXQXcO0pB3K_8uXjiMBGwXpMz_ayg~WyJkcVR2WE14UzBHYTNEb2FHbmU5eDBRIiwgInN1YiIsICJqb2huX2RvZV80MiJd~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJxUVdtakpsMXMxUjRscWhFTkxScnJ3IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJLVXhTNWhFX1hiVmFjckdBYzdFRnd3IiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyIzcXZWSjFCQURwSERTUzkzOVEtUml3IiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyIweEd6bjNNaXFzY3RaSV9PcERsQWJRIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJFUktNMENOZUZKa2FENW1UWFZfWDh3IiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0`                                                                                                                                                                                                                                                                                                                                                                                                                                                 // nolint:lll
const specIssuanceExample1SDJWTV5 = `eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0` // nolint:lll

const specPresentationExample1SDJWTV2 = `eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIk5ZQ29TUktFWXdYZHBlNXlkdUpYQ3h4aHluRVU4ei1iNFR5TmlhcDc3VVkiLCAiU1k4bjJCYmtYOWxyWTNleEhsU3dQUkZYb0QwOUdGOGE5Q1BPLUc4ajIwOCIsICJUUHNHTlBZQTQ2d21CeGZ2MnpuT0poZmRvTjVZMUdrZXpicGFHWkNUMWFjIiwgIlprU0p4eGVHbHVJZFlCYjdDcWtaYkpWbTB3MlY1VXJSZU5UekFRQ1lCanciLCAibDlxSUo5SlRRd0xHN09MRUlDVEZCVnhtQXJ3OFBqeTY1ZEQ2bXRRVkc1YyIsICJvMVNBc0ozM1lNaW9POXBYNVZlQU0xbHh1SEY2aFpXMmtHZGtLS0JuVmxvIiwgInFxdmNxbmN6QU1nWXg3RXlrSTZ3d3RzcHl2eXZLNzkwZ2U3TUJiUS1OdXMiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNTE2MjM5MDIyLCAiZXhwIjogMTUxNjI0NzAyMiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.gieinY5mTgTV69KZJyaFPeIJ9tfXlzCHKfs-HMBO9UIREz6Dh_lpTMrwUUXQXcO0pB3K_8uXjiMBGwXpMz_ayg~WyIweEd6bjNNaXFzY3RaSV9PcERsQWJRIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJxUVdtakpsMXMxUjRscWhFTkxScnJ3IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~eyJhbGciOiAiRVMyNTYifQ.eyJub25jZSI6ICJYWk9VY28xdV9nRVBrbnhTNzhzV1dnIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE2NzA1NzQ0MTh9._TZe98TAQDrV_21TjEKBRKKCt5EO5Q0-MHNZ79qVvBR9gL4nCXBu6c--QDysTgnXk_oe-qVin6EOzHF3Oh9tbQ`                                                                                                                                                                                                                                                                                                                        //nolint:lll
const specPresentationExample1SDJWTV5 = `eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE2ODgxNjA0ODN9.tKnLymr8fQfupOgvMgBK3GCEIDEzhgta4MgnxYm9fWGMkqrz2R5PSkv0I-AXKXtIF6bdZRbjL-t43vC87jVoZQ` //nolint:lll

func TestInterop(t *testing.T) {
	r := require.New(t)

	t.Run("success - Example 1", func(t *testing.T) {
		cfi := specIssuanceExample1SDJWTV2 + common.CombinedFormatSeparator

		claims, err := Parse(cfi,
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithSignatureVerifier(&holder.NoopSignatureVerifier{}),
			// expiry time for example 1 is 2018-01-17 22:43:42 -0500 EST
			// so we have to have great leeway in order to pass test
			WithLeewayForClaimsValidation(10*12*30*24*time.Hour))
		r.NoError(err)

		printObject(t, "Disclosed Claims for Example 1 - All Claims Disclosed", claims)

		var example1ClaimsObj map[string]interface{}
		err = json.Unmarshal([]byte(claimsExample1SDJWTV2), &example1ClaimsObj)
		r.NoError(err)

		var disclosedClaimsForExample1Obj map[string]interface{}
		err = json.Unmarshal([]byte(disclosedAllClaimsForExample1SDJWTV2), &disclosedClaimsForExample1Obj)
		r.NoError(err)

		// expected claims are example 1 claims plus exp, iat, iss, cnf
		r.Equal(len(disclosedClaimsForExample1Obj), len(example1ClaimsObj)+4)

		r.Equal(len(disclosedClaimsForExample1Obj), len(claims))
	})

	t.Run("success - Example 1 SDJWT V5", func(t *testing.T) {
		cfi := specIssuanceExample1SDJWTV5 + common.CombinedFormatSeparator

		claims, err := Parse(cfi,
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithSignatureVerifier(&holder.NoopSignatureVerifier{}),
			// expiry time for example 1 is 2018-01-17 22:43:42 -0500 EST
			// so we have to have great leeway in order to pass test
			WithLeewayForClaimsValidation(10*12*30*24*time.Hour))
		r.NoError(err)

		printObject(t, "Disclosed Claims for Example 1 - All Claims Disclosed", claims)

		var example1ClaimsObj map[string]interface{}
		err = json.Unmarshal([]byte(claimsExample1SDJWTV5), &example1ClaimsObj)
		r.NoError(err)

		var disclosedClaimsForExample1Obj map[string]interface{}
		err = json.Unmarshal([]byte(disclosedAllClaimsForExample1SDJWTV5), &disclosedClaimsForExample1Obj)
		r.NoError(err)

		// expected claims are example 1 claims plus exp, iat, iss, cnf
		r.Equal(len(disclosedClaimsForExample1Obj), len(example1ClaimsObj)+4)

		r.Equal(len(disclosedClaimsForExample1Obj), len(claims))
	})

	t.Run("success - Example 1 with Holder Binding", func(t *testing.T) {
		claims, err := Parse(specPresentationExample1SDJWTV2,
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithHolderSigningAlgorithms([]string{"ES256"}),
			WithSignatureVerifier(&holder.NoopSignatureVerifier{}),
			// expiry time for example 1 is 2018-01-17 22:43:42 -0500 EST
			// so we have to have great leeway in order to pass test
			WithLeewayForClaimsValidation(10*12*30*24*time.Hour))
		r.NoError(err)

		printObject(t, "Disclosed Claims For Example 1 - Partial Disclosure", claims)

		var disclosedPartialClaimsForExample1Obj map[string]interface{}
		err = json.Unmarshal([]byte(disclosedPartialClaimsForExample1SDJWTV2), &disclosedPartialClaimsForExample1Obj)
		r.NoError(err)

		r.Equal(len(disclosedPartialClaimsForExample1Obj), len(claims))
	})

	t.Run("success - Example 1 with Key Binding SDJWT V5", func(t *testing.T) {
		claims, err := Parse(specPresentationExample1SDJWTV5,
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithHolderSigningAlgorithms([]string{"ES256"}),
			WithSignatureVerifier(&holder.NoopSignatureVerifier{}),
			// expiry time for example 1 is 2018-01-17 22:43:42 -0500 EST
			// so we have to have great leeway in order to pass test
			WithLeewayForClaimsValidation(10*12*30*24*time.Hour))
		r.NoError(err)

		printObject(t, "Disclosed Claims For Example 1 - Partial Disclosure", claims)

		var disclosedPartialClaimsForExample1Obj map[string]interface{}
		err = json.Unmarshal([]byte(disclosedPartialClaimsForExample1SDJWTV5), &disclosedPartialClaimsForExample1Obj)
		r.NoError(err)

		r.Equal(len(disclosedPartialClaimsForExample1Obj), len(claims))
	})
}

const claimsExample1SDJWTV2 = `
{
  "sub": "john_doe_42",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "birthdate": "1940-01-01"
}`

const claimsExample1SDJWTV5 = `
{
  "sub": "user_42",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "phone_number_verified": true,
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "birthdate": "1940-01-01",
  "updated_at": 1570000000,
  "nationalities": [
    "US",
    "DE"
  ]
}`

const disclosedAllClaimsForExample1SDJWTV2 = `
{
	"sub": "john_doe_42",
	"given_name": "John",
	"family_name": "Doe",
	"email": "johndoe@example.com",
	"phone_number": "+1-202-555-0101",
	"address": {
		"country": "US",
		"locality": "Anytown",
		"region": "Anystate",
		"street_address": "123 Main St"
	},
	"birthdate": "1940-01-01",
	"exp": 1516247022,
	"iat": 1516239022,
	"iss": "https://example.com/issuer",
	"cnf": {
		"jwk": {
			"crv": "P-256",
			"kty": "EC",
			"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
			"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
		}
	}
}`

const disclosedAllClaimsForExample1SDJWTV5 = `
{
  "sub": "user_42",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "phone_number_verified": true,
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "birthdate": "1940-01-01",
  "updated_at": 1570000000,
  "nationalities": [
    "US",
    "DE"
  ],
  "exp": 1883000000,
  "iat": 1683000000,
  "iss": "https://example.com/issuer",
  "cnf": {
  	"jwk": {
  		"crv": "P-256",
  		"kty": "EC",
  		"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
  		"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
  	}
  }
}`

const disclosedPartialClaimsForExample1SDJWTV2 = `
{
	"family_name": "Doe",
	"given_name": "John",
	"address": {
		"country": "US",
		"locality": "Anytown",
		"region": "Anystate",
		"street_address": "123 Main St"
	},
	"cnf": {
		"jwk": {
			"crv": "P-256",
			"kty": "EC",
			"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
			"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
		}
	},
	"exp": 1516247022,
	"iat": 1516239022,
	"iss": "https://example.com/issuer"
}`

const disclosedPartialClaimsForExample1SDJWTV5 = `
{
	"family_name": "Doe",
    "sub": "user_42",
	"given_name": "John",
	"address": {
		"country": "US",
		"locality": "Anytown",
		"region": "Anystate",
		"street_address": "123 Main St"
	},
    "nationalities": [
      "US"
    ],
	"cnf": {
		"jwk": {
			"crv": "P-256",
			"kty": "EC",
			"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
			"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
		}
	},
	"exp": 1516247022,
	"iat": 1516239022,
	"iss": "https://example.com/issuer"
}`
