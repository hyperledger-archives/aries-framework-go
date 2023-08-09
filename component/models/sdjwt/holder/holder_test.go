/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/issuer"
)

const (
	testIssuer = "https://example.com/issuer"
)

func TestParse(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	claims := map[string]interface{}{"given_name": "Albert"}

	token, e := issuer.New(testIssuer, claims, nil, signer)
	r.NoError(e)
	combinedFormatForIssuance, e := token.Serialize(false)
	r.NoError(e)

	verifier, e := afjwt.NewEd25519Verifier(pubKey)
	r.NoError(e)

	t.Run("success", func(t *testing.T) {
		claims, err := Parse(combinedFormatForIssuance, WithSignatureVerifier(verifier))
		r.NoError(err)
		r.NotNil(claims)
		r.Equal(1, len(claims))
		r.Equal("given_name", claims[0].Name)
		r.Equal("Albert", claims[0].Value)
	})

	t.Run("success - default is no signature verifier", func(t *testing.T) {
		claims, err := Parse(combinedFormatForIssuance)
		r.NoError(err)
		r.Equal(1, len(claims))
		r.Equal("given_name", claims[0].Name)
		r.Equal("Albert", claims[0].Value)
	})

	t.Run("success - spec SD-JWT V2", func(t *testing.T) {
		claims, err := Parse(specSDJWTV2, WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.NoError(err)
		require.NotNil(t, claims)
		require.Equal(t, 7, len(claims))
	})

	t.Run("success - spec SD-JWT V5", func(t *testing.T) {
		claims, err := Parse(specSDJWTV5,
			WithSDJWTV5Validation(true),
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithLeewayForClaimsValidation(10*12*30*24*time.Hour),
			WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.NoError(err)
		require.NotNil(t, claims)
		require.Equal(t, 10, len(claims))
	})

	t.Run("success - VC example", func(t *testing.T) {
		claims, err := Parse(vcCombinedFormatForIssuance, WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.NoError(err)
		require.NotNil(t, claims)
		require.Equal(t, 4, len(claims))
	})

	t.Run("success - complex claims", func(t *testing.T) {
		complexClaims := createComplexClaims()

		token, e := issuer.New(testIssuer, complexClaims, nil, signer,
			issuer.WithStructuredClaims(true))
		r.NoError(e)
		cfi, e := token.Serialize(false)
		r.NoError(e)

		claims, err := Parse(cfi, WithSignatureVerifier(verifier))
		r.NoError(err)
		r.NotNil(claims)
		r.Equal(10, len(claims))
	})

	t.Run("error - additional disclosure", func(t *testing.T) {
		claims, err := Parse(fmt.Sprintf("%s~%s", combinedFormatForIssuance, additionalDisclosure),
			WithSignatureVerifier(verifier))
		r.Error(err)
		r.Nil(claims)
		r.Contains(err.Error(),
			"disclosure digest 'qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus' not found in SD-JWT disclosure digests")
	})

	t.Run("success - with detached payload", func(t *testing.T) {
		jwsParts := strings.Split(combinedFormatForIssuance, ".")
		jwsDetached := fmt.Sprintf("%s..%s", jwsParts[0], jwsParts[2])

		jwsPayload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])
		require.NoError(t, err)

		sdJWT, err := Parse(jwsDetached,
			WithSignatureVerifier(verifier), WithJWTDetachedPayload(jwsPayload))
		r.NoError(err)
		r.NotNil(r, sdJWT)
	})

	t.Run("error - invalid claims", func(t *testing.T) {
		// claims is not JSON
		sdJWTSerialized, err := buildJWS(signer, "not JSON")
		r.NoError(err)

		claims, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Nil(claims)
		r.Contains(err.Error(), "read JWT claims from JWS payload")
	})

	t.Run("error - applySDJWTV5Validation key binding supplied", func(t *testing.T) {
		holderSigner, _, err := setUpHolderBinding()
		if err != nil {
			fmt.Println("failed to set-up test: %w", err.Error())
		}

		holderVerification, err := CreateHolderVerification(&BindingInfo{
			Payload: BindingPayload{
				Nonce:    "nonce",
				Audience: "https://test.com/verifier",
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
			Signer: holderSigner,
		})
		r.NoError(err)

		cfp := specSDJWTV5 + common.CombinedFormatSeparator + holderVerification

		claims, err := Parse(cfp,
			WithSDJWTV5Validation(true),
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.Nil(claims)
		r.Error(err)
		r.ErrorContains(err, "unexpected key binding JWT supplied")
	})

	t.Run("error - applySDJWTV5Validation unexpected typ header", func(t *testing.T) {
		complexClaims := createComplexClaims()

		token, e := issuer.New(testIssuer, complexClaims, map[string]interface{}{
			jose.HeaderType: "JWT",
		}, signer,
			issuer.WithStructuredClaims(true))
		r.NoError(e)
		cfi, e := token.Serialize(false)
		r.NoError(e)

		claims, err := Parse(cfi,
			WithSDJWTV5Validation(true),
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithExpectedTypHeader("vc+sd-jwt"),
			WithSignatureVerifier(verifier))
		r.Nil(claims)
		r.Error(err)
		r.ErrorContains(err, "unexpected typ \"JWT\"")
	})

	t.Run("error - applySDJWTV5Validation signing alg", func(t *testing.T) {
		claims, err := Parse(specSDJWTV5,
			WithSDJWTV5Validation(true),
			WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.Nil(claims)
		r.Error(err)
		r.ErrorContains(err, "failed to verify issuer signing algorithm: alg 'ES256' is not in the allowed list")
	})

	t.Run("error - applySDJWTV5Validation leeway claims", func(t *testing.T) {
		claims, err := Parse(specSDJWTV5,
			WithSDJWTV5Validation(true),
			WithIssuerSigningAlgorithms([]string{"ES256"}),
			WithLeewayForClaimsValidation(-time.Hour*24*365*10),
			WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.Nil(claims)
		r.ErrorContains(err, " validation failed, token is expired (exp)")
	})
}

func TestCreatePresentation(t *testing.T) {
	r := require.New(t)

	_, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	claims := map[string]interface{}{"given_name": "Albert"}

	token, e := issuer.New(testIssuer, claims, nil, signer)
	r.NoError(e)
	combinedFormatForIssuance, e := token.Serialize(false)
	r.NoError(e)

	cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

	claimsToDisclose := []string{cfi.Disclosures[0]}

	t.Run("success", func(t *testing.T) {
		combinedFormatForPresentation, err := CreatePresentation(combinedFormatForIssuance, claimsToDisclose)
		r.NoError(err)
		require.NotNil(t, combinedFormatForPresentation)
		require.Equal(t, combinedFormatForIssuance+common.CombinedFormatSeparator, combinedFormatForPresentation)
	})

	t.Run("success - with holder verification", func(t *testing.T) {
		_, holderPrivKey, e := ed25519.GenerateKey(rand.Reader)
		r.NoError(e)

		holderSigner := afjwt.NewEd25519Signer(holderPrivKey)

		combinedFormatForPresentation, err := CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
			WithHolderBinding(&BindingInfo{
				Payload: BindingPayload{
					Audience: "https://example.com/verifier",
					Nonce:    "nonce",
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
				Signer: holderSigner,
			}))
		r.NoError(err)
		r.NotEmpty(combinedFormatForPresentation)
		r.Contains(combinedFormatForPresentation, combinedFormatForIssuance+common.CombinedFormatSeparator)
	})

	t.Run("error - failed to create holder verification due to signing error", func(t *testing.T) {
		combinedFormatForPresentation, err := CreatePresentation(combinedFormatForIssuance, claimsToDisclose,
			WithHolderVerification(&BindingInfo{
				Payload: BindingPayload{},
				Signer:  &mockSigner{Err: fmt.Errorf("signing error")},
			}))

		r.Error(err)
		r.Empty(combinedFormatForPresentation)

		r.Contains(err.Error(),
			"failed to create holder verification: create JWS: sign JWS: sign JWS verification data: signing error")
	})

	t.Run("error - no disclosure(s)", func(t *testing.T) {
		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

		combinedFormatForPresentation, err := CreatePresentation(cfi.SDJWT, claimsToDisclose)
		r.Error(err)
		r.Empty(combinedFormatForPresentation)
		r.Contains(err.Error(), "no disclosures found in SD-JWT")
	})

	t.Run("error - disclosure not found", func(t *testing.T) {
		combinedFormatForPresentation, err := CreatePresentation(combinedFormatForIssuance,
			[]string{"non_existent"})
		r.Error(err)
		r.Empty(combinedFormatForPresentation)
		r.Contains(err.Error(), "disclosure 'non_existent' not found")
	})
}

func TestGetClaims(t *testing.T) {
	r := require.New(t)

	t.Run("success", func(t *testing.T) {
		claims, err := getClaims([]string{additionalDisclosure}, crypto.SHA256)
		r.NoError(err)
		r.Len(claims, 1)
	})

	t.Run("error - not base64 encoded ", func(t *testing.T) {
		claims, err := getClaims([]string{"!!!"}, crypto.SHA256)
		r.Error(err)
		r.Nil(claims)
		r.Contains(err.Error(), "failed to decode disclosure")
	})
}

func TestWithJWTDetachedPayload(t *testing.T) {
	detachedPayloadOpt := WithJWTDetachedPayload([]byte("payload"))
	require.NotNil(t, detachedPayloadOpt)

	opts := &parseOpts{}
	detachedPayloadOpt(opts)
	require.Equal(t, []byte("payload"), opts.detachedPayload)
}

func buildJWS(signer jose.Signer, claims interface{}) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := jose.NewJWS(nil, nil, claimsBytes, signer)
	if err != nil {
		return "", err
	}

	return jws.SerializeCompact(false)
}

// Signer defines JWS Signer interface. It makes signing of data and provides custom JWS headers relevant to the signer.
type mockSigner struct {
	Err error
}

// Sign signs.
func (m *mockSigner) Sign(_ []byte) ([]byte, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return nil, nil
}

// Headers provides JWS headers.
func (m *mockSigner) Headers() jose.Headers {
	headers := make(jose.Headers)
	headers["alg"] = "EdDSA"

	return headers
}

func createComplexClaims() map[string]interface{} {
	claims := map[string]interface{}{
		"sub":          "john_doe_42",
		"given_name":   "John",
		"family_name":  "Doe",
		"email":        "johndoe@example.com",
		"phone_number": "+1-202-555-0101",
		"birthdate":    "1940-01-01",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"locality":       "Anytown",
			"region":         "Anystate",
			"country":        "US",
		},
	}

	return claims
}

// nolint: lll
const additionalDisclosure = `WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`

// nolint: lll
const specSDJWTV2 = `eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJfc2QiOiBbIk5ZQ29TUktFWXdYZHBlNXlkdUpYQ3h4aHluRVU4ei1iNFR5TmlhcDc3VVkiLCAiU1k4bjJCYmtYOWxyWTNleEhsU3dQUkZYb0QwOUdGOGE5Q1BPLUc4ajIwOCIsICJUUHNHTlBZQTQ2d21CeGZ2MnpuT0poZmRvTjVZMUdrZXpicGFHWkNUMWFjIiwgIlprU0p4eGVHbHVJZFlCYjdDcWtaYkpWbTB3MlY1VXJSZU5UekFRQ1lCanciLCAibDlxSUo5SlRRd0xHN09MRUlDVEZCVnhtQXJ3OFBqeTY1ZEQ2bXRRVkc1YyIsICJvMVNBc0ozM1lNaW9POXBYNVZlQU0xbHh1SEY2aFpXMmtHZGtLS0JuVmxvIiwgInFxdmNxbmN6QU1nWXg3RXlrSTZ3d3RzcHl2eXZLNzkwZ2U3TUJiUS1OdXMiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNTE2MjM5MDIyLCAiZXhwIjogMTUxNjI0NzAyMiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDhaZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1UW9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkwwRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTRxUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifX19.xqgKrDO6dK_oBL3fiqdcq_elaIGxM6Z-RyuysglGyddR1O1IiE3mIk8kCpoqcRLR88opkVWN2392K_XYfAuAmeT9kJVisD8ZcgNcv-MQlWW9s8WaViXxBRe7EZWkWRQcQVR6jf95XZ5H2-_KA54POq3L42xjk0y5vDr8yc08Reak6vvJVvjXpp-Wk6uxsdEEAKFspt_EYIvISFJhfTuQqyhCjnaW13X312MSQBPwjbHn74ylUqVLljDvqcemxeqjh42KWJq4C3RqNJ7anA2i3FU1kB4-KNZWsijY7-op49iL7BrnIBxdlAMrbHEkoGTbFWdl7Ki17GHtDxxa1jaxQg~WyJkcVR2WE14UzBHYTNEb2FHbmU5eDBRIiwgInN1YiIsICJqb2huX2RvZV80MiJd~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJxUVdtakpsMXMxUjRscWhFTkxScnJ3IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJLVXhTNWhFX1hiVmFjckdBYzdFRnd3IiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyIzcXZWSjFCQURwSERTUzkzOVEtUml3IiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyIweEd6bjNNaXFzY3RaSV9PcERsQWJRIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJFUktNMENOZUZKa2FENW1UWFZfWDh3IiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0`

// nolint: lll
const specSDJWTV5 = `eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.kmx687kUBiIDvKWgo2Dub-TpdCCRLZwtD7TOj4RoLsUbtFBI8sMrtH2BejXtm_P6fOAjKAVc_7LRNJFgm3PJhg~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0`

// nolint: lll
const vcCombinedFormatForIssuance = `eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjEuNjczOTg3NTQ3ZSswOSwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzE4NzIiLCJuYmYiOjEuNjczOTg3NTQ3ZSswOSwic3ViIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZDlYemtRbVJMQncxSXpfeHVGUmVLMUItRmpCdTdjT0N3RTlOR2F1d251SSJ9fSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbInBBdjJUMU10YmRXNGttUUdxT1VVRUpjQmdTZi1mSFRHV2xQVUV4aWlIbVEiLCI2dDlBRUJCQnEzalZwckJ3bGljOGhFWnNNSmxXSXhRdUw5c3ExMzJZTnYwIl0sImRlZ3JlZSI6eyJfc2QiOlsibzZzV2h4RjcxWHBvZ1cxVUxCbU90bjR1SXFGdjJ3ODF6emRuelJXdlpqYyIsIi1yRklXbU1YR3ZXX0FIYVEtODhpMy11ZzRUVjhLUTg5TjdmZmtneFc2X2MiXX0sImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIn0sImZpcnN0X25hbWUiOiJGaXJzdCBuYW1lIiwiaWQiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMTg3MiIsImluZm8iOiJJbmZvIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMS0xN1QyMjozMjoyNy40NjgxMDk4MTcrMDI6MDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJsYXN0X25hbWUiOiJMYXN0IG5hbWUiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX0.GcfSA6NkONxdsm5Lxj9-988eWx1ZvMz5vJ1uh2x8UK1iKIeQLmhsWpA_34RbtAm2HnuoxW4_ZGeiHBzQ1GLTDQ~WyJFWkVDRVZ1YWVJOXhZWmlWb3VMQldBIiwidHlwZSIsIkJhY2hlbG9yRGVncmVlIl0~WyJyMno1UzZMa25FRTR3TWwteFB0VEx3IiwiZGVncmVlIiwiTUlUIl0~WyJ2VkhfaGhNQy1aSUt5WFdtdDUyOWpnIiwic3BvdXNlIiwiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIl0~WyJrVzh0WVVwbVl1VmRoZktFT050TnFnIiwibmFtZSIsIkpheWRlbiBEb2UiXQ`
