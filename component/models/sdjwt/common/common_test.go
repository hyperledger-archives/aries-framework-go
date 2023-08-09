/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"crypto"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"

	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

const (
	defaultHash = crypto.SHA256

	testAlg = "sha-256"
)

//go:embed testdata/full_disclosures_v5.json
var fullDisclosuresV5TestData []byte

//go:embed testdata/array_element_and_one_missing_v5.json
var arrayElementAndOneMissingV5TestData []byte

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

func TestParseCombinedFormatForIssuance(t *testing.T) {
	t.Run("success - SD-JWT only", func(t *testing.T) {
		cfi := ParseCombinedFormatForIssuance(testCombinedFormatForIssuance)
		require.Equal(t, testSDJWT, cfi.SDJWT)
		require.Equal(t, 1, len(cfi.Disclosures))

		require.Equal(t, testCombinedFormatForIssuance, cfi.Serialize())
	})
	t.Run("success - spec example", func(t *testing.T) {
		cfi := ParseCombinedFormatForIssuance(specCombinedFormatForIssuance)
		require.Equal(t, 7, len(cfi.Disclosures))

		require.Equal(t, specCombinedFormatForIssuance, cfi.Serialize())
	})
	t.Run("success - AFG generated", func(t *testing.T) {
		cfi := ParseCombinedFormatForIssuance(testSDJWT)
		require.Equal(t, testSDJWT, cfi.SDJWT)
		require.Equal(t, 0, len(cfi.Disclosures))

		require.Equal(t, testSDJWT, cfi.Serialize())
	})
}

func TestParseCombinedFormatForPresentation(t *testing.T) {
	const testHolderBinding = "holder.binding.jwt"

	testCombinedFormatForPresentation := testCombinedFormatForIssuance + CombinedFormatSeparator

	t.Run("success - AFG example", func(t *testing.T) {
		cfp := ParseCombinedFormatForPresentation(testCombinedFormatForPresentation)
		require.Equal(t, testSDJWT, cfp.SDJWT)
		require.Equal(t, 1, len(cfp.Disclosures))
		require.Empty(t, cfp.HolderVerification)

		require.Equal(t, testCombinedFormatForPresentation, cfp.Serialize())
	})

	t.Run("success - spec example", func(t *testing.T) {
		cfp := ParseCombinedFormatForPresentation(specCombinedFormatForIssuance + CombinedFormatSeparator)
		require.Equal(t, 7, len(cfp.Disclosures))
		require.Empty(t, cfp.HolderVerification)

		require.Equal(t, specCombinedFormatForIssuance+CombinedFormatSeparator, cfp.Serialize())
	})

	t.Run("success - AFG test with holder binding", func(t *testing.T) {
		testCFI := testCombinedFormatForPresentation + testHolderBinding
		cfp := ParseCombinedFormatForPresentation(testCFI)
		require.Equal(t, testSDJWT, cfp.SDJWT)
		require.Equal(t, 1, len(cfp.Disclosures))
		require.Equal(t, testHolderBinding, cfp.HolderVerification)

		require.Equal(t, testCFI, cfp.Serialize())
	})

	t.Run("success - SD-JWT only", func(t *testing.T) {
		cfp := ParseCombinedFormatForPresentation(testSDJWT)
		require.Equal(t, testSDJWT, cfp.SDJWT)
		require.Equal(t, 0, len(cfp.Disclosures))
		require.Empty(t, cfp.HolderVerification)

		require.Equal(t, testSDJWT, cfp.Serialize())
	})

	t.Run("success - SD-JWT + holder binding", func(t *testing.T) {
		testCFI := testSDJWT + CombinedFormatSeparator + testHolderBinding

		cfp := ParseCombinedFormatForPresentation(testCFI)
		require.Equal(t, testSDJWT, cfp.SDJWT)
		require.Equal(t, 0, len(cfp.Disclosures))
		require.Equal(t, testHolderBinding, cfp.HolderVerification)

		require.Equal(t, testCFI, cfp.Serialize())
	})

	t.Run("success - SD-JWT + multiple disclosures only", func(t *testing.T) {
		specExample2bPresentation := fmt.Sprintf("%s%s", specExample2bJWT, specExample2bDisclosures)

		cfp := ParseCombinedFormatForPresentation(specExample2bPresentation)
		require.Equal(t, specExample2bJWT, cfp.SDJWT)
		require.Equal(t, 6, len(cfp.Disclosures))
		require.Empty(t, cfp.HolderVerification)

		require.Equal(t, specExample2bPresentation, cfp.Serialize())
	})
}

func TestGetDisclosureClaims(t *testing.T) {
	r := require.New(t)

	t.Run("success", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuance)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		token, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.NoError(err)

		hash, err := GetCryptoHashFromClaims(token.Payload)
		r.NoError(err)

		disclosureClaims, err := GetDisclosureClaims(sdJWT.Disclosures, hash)
		r.NoError(err)
		r.Len(disclosureClaims, 1)

		r.Equal("given_name", disclosureClaims[0].Name)
		r.Equal("John", disclosureClaims[0].Value)
	})

	t.Run("full disclosures V5", func(t *testing.T) {
		var disData []string
		r.NoError(json.Unmarshal(fullDisclosuresV5TestData, &disData))

		parsed, err := GetDisclosureClaims(disData, crypto.SHA256)
		r.NoError(err)
		r.Len(parsed, 10)

		var address *DisclosureClaim
		for _, cl := range parsed {
			if cl.Name == "address" {
				address = cl
				break
			}
		}

		r.Equal(map[string]interface{}{
			"extraArrInclude": []interface{}{
				"UA", "PL",
			},
			"extra": map[string]interface{}{
				"recursive": map[string]interface{}{
					"key1": "value1",
				},
			},
			"region":         "Sachsen-Anhalt",
			"country":        "DE",
			"street_address": "Schulstr. 12",
			"locality":       "Schulpforta",
			"extraArr": []interface{}{
				"Extra1", "Extra2",
			},
		}, address.Value)
	})

	t.Run("array element and one value missing V5", func(t *testing.T) {
		// - 	"WyJ5WElBaTZSb1Y1eDV2X3lsVm1wXzhBIiwibG9jYWxpdHkiLCJTY2h1bHBmb3J0YSJd" locality
		// - 	"WyJURWtwSjJkYWxraGltUUVLd25Cblp3IiwiVUEiXQ", UA
		var disData []string
		r.NoError(json.Unmarshal(arrayElementAndOneMissingV5TestData, &disData))
		parsed, err := GetDisclosureClaims(disData, crypto.SHA256)
		r.NoError(err)
		r.Len(parsed, 8)

		var address *DisclosureClaim
		for _, cl := range parsed {
			if cl.Name == "address" {
				address = cl
				break
			}
		}

		r.Equal(map[string]interface{}{
			"extraArrInclude": []interface{}{
				"PL",
			},
			"extra": map[string]interface{}{
				"recursive": map[string]interface{}{
					"key1": "value1",
				},
			},
			"region":         "Sachsen-Anhalt",
			"country":        "DE",
			"street_address": "Schulstr. 12",
			"extraArr": []interface{}{
				"Extra1", "Extra2",
			},
		}, address.Value)
	})

	t.Run("error - invalid disclosure format (not encoded)", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testSDJWT + "~xyz")
		require.Equal(t, 1, len(sdJWT.Disclosures))

		token, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.NoError(err)

		hash, err := GetCryptoHashFromClaims(token.Payload)
		r.NoError(err)

		disclosureClaims, err := GetDisclosureClaims(sdJWT.Disclosures, hash)
		r.Error(err)
		r.Nil(disclosureClaims)
		r.Contains(err.Error(), "failed to unmarshal disclosure array")
	})

	t.Run("error - invalid disclosure array (less then 2 parts)", func(t *testing.T) {
		disclosureArr := []interface{}{"name"}
		disclosureJSON, err := json.Marshal(disclosureArr)
		require.NoError(t, err)

		sdJWT := ParseCombinedFormatForIssuance(fmt.Sprintf("%s~%s", testSDJWT,
			base64.RawURLEncoding.EncodeToString(disclosureJSON)))
		require.Equal(t, 1, len(sdJWT.Disclosures))

		token, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.NoError(err)

		hash, err := GetCryptoHashFromClaims(token.Payload)
		r.NoError(err)

		disclosureClaims, err := GetDisclosureClaims(sdJWT.Disclosures, hash)
		r.Error(err)
		r.Nil(disclosureClaims)
		r.Contains(err.Error(), "disclosure array size[1] must be greater 2")
	})

	t.Run("error - invalid disclosure array (name is not a string)", func(t *testing.T) {
		disclosureArr := []interface{}{"salt", 123, "value"}
		disclosureJSON, err := json.Marshal(disclosureArr)
		require.NoError(t, err)

		sdJWT := ParseCombinedFormatForIssuance(fmt.Sprintf("%s~%s", testSDJWT,
			base64.RawURLEncoding.EncodeToString(disclosureJSON)))
		require.Equal(t, 1, len(sdJWT.Disclosures))

		token, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		r.NoError(err)

		hash, err := GetCryptoHashFromClaims(token.Payload)
		r.NoError(err)

		disclosureClaims, err := GetDisclosureClaims(sdJWT.Disclosures, hash)
		r.Error(err)
		r.Nil(disclosureClaims)
		r.Contains(err.Error(), "disclosure name type[float64] must be string")
	})
}

func TestGetDisclosedClaims(t *testing.T) {
	r := require.New(t)

	cfi := ParseCombinedFormatForIssuance(testCombinedFormatForIssuance)
	r.Equal(testSDJWT, cfi.SDJWT)
	r.Equal(1, len(cfi.Disclosures))

	token, _, err := afjwt.Parse(cfi.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
	r.NoError(err)

	hash, err := GetCryptoHashFromClaims(token.Payload)
	r.NoError(err)

	disclosureClaims, err := GetDisclosureClaims(cfi.Disclosures, hash)
	r.NoError(err)

	var claims map[string]interface{}
	err = token.DecodeClaims(&claims)
	r.NoError(err)

	t.Run("success", func(t *testing.T) {
		disclosedClaims, err := GetDisclosedClaims(disclosureClaims, claims)
		r.NoError(err)
		r.NotNil(disclosedClaims)

		r.Equal(5, len(disclosedClaims))
		r.NotEmpty(disclosedClaims["iat"])
		r.NotEmpty(disclosedClaims["nbf"])
		r.NotEmpty(disclosedClaims["iss"])
		r.Equal("https://example.com/issuer", disclosedClaims["iss"])
		r.Equal("John", disclosedClaims["given_name"])
	})

	t.Run("success V5", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		disclosureClaimsV5, err := GetDisclosureClaims(sdJWT.Disclosures, crypto.SHA256)
		require.NoError(t, err)

		disclosedClaims, err := GetDisclosedClaims(disclosureClaimsV5, signedJWT.Payload)
		r.NoError(err)
		r.NotNil(disclosedClaims)

		r.Equal(2, len(disclosedClaims))
		r.Equal("https://example.com/issuer", disclosedClaims["iss"])
		r.Equal(map[string]interface{}{
			"locality":     "Schulpforta",
			"region":       "Sachsen-Anhalt",
			"cities":       []interface{}{"Albuquerque", "El Paso"},
			"countryCodes": []interface{}{"UA", "PL"},
			"extra": map[string]interface{}{
				"recursive": map[string]interface{}{
					"key1": "value1",
				},
			},
		}, disclosedClaims["address"])
	})

	t.Run("success V5 not all disclosures provided", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		disclosureClaimsV5, err := GetDisclosureClaims(sdJWT.Disclosures, crypto.SHA256)
		require.NoError(t, err)

		var disclosuresLimitedList []*DisclosureClaim
		for _, d := range disclosureClaimsV5 {
			// Remove UA array element
			if v, ok := d.Value.(string); ok && v == "UA" {
				continue
			}
			// Remove PL array element
			if v, ok := d.Value.(string); ok && v == "PL" {
				continue
			}
			// Remove Albuquerque array element
			if v, ok := d.Value.(string); ok && v == "Albuquerque" {
				continue
			}
			// Remove one sd element
			if v, ok := d.Value.(string); ok && v == "Schulpforta" {
				continue
			}

			disclosuresLimitedList = append(disclosuresLimitedList, d)
		}

		disclosedClaims, err := GetDisclosedClaims(disclosuresLimitedList, signedJWT.Payload)
		r.NoError(err)
		r.NotNil(disclosedClaims)

		r.Equal(2, len(disclosedClaims))
		r.Equal("https://example.com/issuer", disclosedClaims["iss"])
		r.Equal(map[string]interface{}{
			"region": "Sachsen-Anhalt",
			"cities": []interface{}{"El Paso"},
			"extra": map[string]interface{}{
				"recursive": map[string]interface{}{
					"key1": "value1",
				},
			},
		}, disclosedClaims["address"])
	})

	t.Run("success - with complex object", func(t *testing.T) {
		testClaims := utils.CopyMap(claims)

		additionalDigest, err := GetHash(crypto.SHA256, additionalSDDisclosure)
		r.NoError(err)

		parentObj := make(map[string]interface{})
		parentObj["last_name"] = "Brown"
		parentObj[SDKey] = []interface{}{additionalDigest}

		testClaims["father"] = parentObj

		printObject(t, "Complex Claims", testClaims)

		disclosedClaims, err := GetDisclosedClaims(append(disclosureClaims,
			&DisclosureClaim{
				Digest:        additionalDigest,
				Disclosure:    additionalSDDisclosure,
				Salt:          "",
				Elements:      disclosureElementsAmountForSDDigest,
				Type:          DisclosureClaimTypePlainText,
				Version:       SDJWTVersionV2,
				Name:          "key-x",
				Value:         "value-y",
				IsValueParsed: false,
			}),
			testClaims)
		r.NoError(err)
		r.NotNil(disclosedClaims)

		printObject(t, "Disclosed Claims", disclosedClaims)

		r.Equal(6, len(disclosedClaims))
		r.Equal("John", disclosedClaims["given_name"])
		r.Equal("value-y", disclosedClaims["father"].(map[string]interface{})["key-x"])
	})

	t.Run("success - claim value contains _sd", func(t *testing.T) {
		testClaims := utils.CopyMap(claims)

		additionalDigest, err := GetHash(crypto.SHA256, additionalSDDisclosure)
		r.NoError(err)

		parentObj := make(map[string]interface{})
		parentObj["last_name"] = "Smith"
		parentObj[SDKey] = []interface{}{additionalDigest}

		testClaims["father"] = parentObj

		disclosedClaims, err := GetDisclosedClaims(append(disclosureClaims,
			&DisclosureClaim{
				Digest:     additionalDigest,
				Disclosure: additionalSDDisclosure,
				Salt:       "",
				Elements:   disclosureElementsAmountForSDDigest,
				Type:       DisclosureClaimTypeObject,
				Version:    SDJWTVersionV2,
				Name:       "key-x",
				Value: map[string]interface{}{
					"_sd": []interface{}{"test-digest"},
				},
				IsValueParsed: false,
			}),
			testClaims)
		r.NoError(err)
		r.NotNil(disclosedClaims)
	})

	t.Run("error - same claim key at the same level ", func(t *testing.T) {
		testClaims := utils.CopyMap(claims)

		parentObj := make(map[string]interface{})
		parentObj["given_name"] = "Albert"
		parentObj[SDKey] = claims[SDKey]

		testClaims["father"] = parentObj
		delete(testClaims, SDKey)

		printObject(t, "Complex Claims", testClaims)

		disclosedClaims, err := GetDisclosedClaims(disclosureClaims, testClaims)
		r.Error(err)
		r.Nil(disclosedClaims)
		r.Contains(err.Error(),
			"failed to process disclosed claims: claim name 'given_name' already exists at the same level")
	})

	t.Run("error - digest included in more than one spot ", func(t *testing.T) {
		testClaims := utils.CopyMap(claims)

		parentObj := make(map[string]interface{})
		parentObj["last_name"] = "Smith"
		parentObj[SDKey] = claims[SDKey]

		testClaims["father"] = parentObj

		printObject(t, "Complex Claims", testClaims)

		disclosedClaims, err := GetDisclosedClaims(disclosureClaims, testClaims)
		r.Error(err)
		r.Nil(disclosedClaims)
		r.Contains(err.Error(),
			"failed to process disclosed claims: digest 'qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus' has been included in more than one place") //nolint:lll
	})

	t.Run("error - with complex object", func(t *testing.T) {
		testClaims := utils.CopyMap(claims)

		parentObj := make(map[string]interface{})
		parentObj["given_name"] = "Albert"
		parentObj[SDKey] = []interface{}{0}

		testClaims["father"] = parentObj

		disclosedClaims, err := GetDisclosedClaims(disclosureClaims, testClaims)
		r.Error(err)
		r.Nil(disclosedClaims)

		r.Contains(err.Error(),
			"failed to process disclosed claims: get disclosure digests: entry item type[int] is not a string")
	})

	t.Run("error - no _sd_alg", func(t *testing.T) {
		disclosedClaims, err := GetDisclosedClaims(disclosureClaims, make(map[string]interface{}))
		r.Error(err)
		r.Nil(disclosedClaims)

		r.Contains(err.Error(),
			"failed to get crypto hash from claims: _sd_alg must be present in SD-JWT")
	})

	t.Run("error - invalid _sd item", func(t *testing.T) {
		testClaims := make(map[string]interface{})
		testClaims[SDAlgorithmKey] = testAlg
		testClaims[SDKey] = []interface{}{0}

		disclosedClaims, err := GetDisclosedClaims(disclosureClaims, testClaims)
		r.Error(err)
		r.Nil(disclosedClaims)

		r.Contains(err.Error(),
			"failed to process disclosed claims: get disclosure digests: entry item type[int] is not a string")
	})

	t.Run("error - invalid _sd type", func(t *testing.T) {
		testClaims := make(map[string]interface{})
		testClaims[SDAlgorithmKey] = "sha-256"
		testClaims[SDKey] = "not-array"

		disclosedClaims, err := GetDisclosedClaims(disclosureClaims, testClaims)
		r.Error(err)
		r.Nil(disclosedClaims)

		r.Contains(err.Error(),
			"failed to process disclosed claims: get disclosure digests: entry type[string] is not an array")
	})
}

func TestGetCryptoHash(t *testing.T) {
	r := require.New(t)

	t.Run("success", func(t *testing.T) {
		hash, err := GetCryptoHash("sha-256")
		r.NoError(err)
		r.Equal(crypto.SHA256, hash)

		hash, err = GetCryptoHash("sha-384")
		r.NoError(err)
		r.Equal(crypto.SHA384, hash)

		hash, err = GetCryptoHash("sha-512")
		r.NoError(err)
		r.Equal(crypto.SHA512, hash)
	})

	t.Run("error - not supported", func(t *testing.T) {
		hash, err := GetCryptoHash("invalid")
		r.Error(err)
		r.Equal(crypto.Hash(0), hash)
		r.Contains(err.Error(), "_sd_alg 'invalid' not supported")
	})
}

func TestGetSDAlg(t *testing.T) {
	r := require.New(t)

	t.Run("success", func(t *testing.T) {
		claims := map[string]interface{}{
			"_sd_alg": "sha-256",
		}

		alg, err := GetSDAlg(claims)
		r.NoError(err)
		r.Equal("sha-256", alg)
	})

	t.Run("success - algorithm is in VC credential subject", func(t *testing.T) {
		claims := map[string]interface{}{
			"given_name": "John",
			"vc": map[string]interface{}{
				"_sd_alg": "sha-256",
			},
		}

		alg, err := GetSDAlg(claims)
		r.NoError(err)
		r.Equal("sha-256", alg)
	})

	t.Run("error - algorithm not found (no vc)", func(t *testing.T) {
		alg, err := GetSDAlg(make(map[string]interface{}))
		r.Error(err)
		r.Empty(alg)

		r.Contains(err.Error(), "_sd_alg must be present in SD-JWT")
	})

	t.Run("error - algorithm not found (vc is empty)", func(t *testing.T) {
		claims := map[string]interface{}{
			"vc": map[string]interface{}{},
		}

		alg, err := GetSDAlg(claims)
		r.Error(err)
		r.Empty(alg)

		r.Contains(err.Error(), "_sd_alg must be present in SD-JWT")
	})

	t.Run("error - algorithm not found (vc is not a map)", func(t *testing.T) {
		claims := map[string]interface{}{
			"vc": "invalid",
		}

		alg, err := GetSDAlg(claims)
		r.Error(err)
		r.Empty(alg)

		r.Contains(err.Error(), "_sd_alg must be present in SD-JWT")
	})

	t.Run("error - algorithm must be a string", func(t *testing.T) {
		claims := map[string]interface{}{
			"vc": map[string]interface{}{
				"_sd_alg": 123,
			},
		}

		alg, err := GetSDAlg(claims)
		r.Error(err)
		r.Empty(alg)

		r.Contains(err.Error(), "_sd_alg must be a string")
	})

	t.Run("error - algorithm must be a string", func(t *testing.T) {
		claims := map[string]interface{}{
			"_sd_alg": 123,
		}

		alg, err := GetSDAlg(claims)
		r.Error(err)
		r.Empty(alg)

		r.Contains(err.Error(), "_sd_alg must be a string")
	})
}

func TestGetCNF(t *testing.T) {
	r := require.New(t)

	t.Run("success - cnf is at the top level", func(t *testing.T) {
		claims := make(map[string]interface{})
		claims["cnf"] = map[string]interface{}{
			"jwk": map[string]interface{}{
				"kty": "RSA",
				"e":   "AQAB",
				"n":   "pm4bOHBg-oYhAyPWzR56AWX3rUIXp11",
			},
		}

		cnf, err := GetCNF(claims)
		r.NoError(err)
		r.NotEmpty(cnf["jwk"])
	})

	t.Run("success - cnf is in VC", func(t *testing.T) {
		var payload map[string]interface{}

		err := json.Unmarshal([]byte(vcSample), &payload)
		require.NoError(t, err)

		cnf, err := GetCNF(payload)
		r.NoError(err)
		r.NotEmpty(cnf["jwk"])
	})

	t.Run("error - cnf not found (empty claims)", func(t *testing.T) {
		cnf, err := GetCNF(make(map[string]interface{}))
		r.Error(err)
		r.Empty(cnf)

		r.Contains(err.Error(), "cnf must be present in SD-JWT")
	})

	t.Run("error - cnf is not an object", func(t *testing.T) {
		claims := make(map[string]interface{})
		claims["cnf"] = "abc"

		cnf, err := GetCNF(claims)
		r.Error(err)
		r.Empty(cnf)

		r.Contains(err.Error(), "cnf must be an object")
	})
}

func TestKeyExistInMap(t *testing.T) {
	r := require.New(t)

	key := "_sd"

	t.Run("true - claims contain _sd key (top level object)", func(t *testing.T) {
		claims := map[string]interface{}{
			key: "whatever",
		}

		exists := KeyExistsInMap(key, claims)
		r.True(exists)
	})

	t.Run("true - claims contain _sd key (inner object)", func(t *testing.T) {
		claims := map[string]interface{}{
			"degree": map[string]interface{}{
				key:    "whatever",
				"type": "BachelorDegree",
			},
		}

		exists := KeyExistsInMap(key, claims)
		r.True(exists)
	})

	t.Run("false - _sd key not present in claims", func(t *testing.T) {
		claims := map[string]interface{}{
			"key-x": "value-y",
			"degree": map[string]interface{}{
				"key-x": "whatever",
				"type":  "BachelorDegree",
			},
		}

		exists := KeyExistsInMap(key, claims)
		r.False(exists)
	})
}

func TestGetKeyFromVC(t *testing.T) {
	type args struct {
		key    string
		claims map[string]interface{}
	}

	tests := []struct {
		name  string
		args  args
		want  interface{}
		want1 bool
	}{
		{
			name: "success - vc root claim does not exist",
			args: args{
				key: "credentialSubject",
				claims: map[string]interface{}{
					"credentialSubject": 123,
				},
			},
			want:  123,
			want1: true,
		},
		{
			name: "success - vc root claim exist",
			args: args{
				key: "credentialSubject",
				claims: map[string]interface{}{
					"vc": map[string]interface{}{
						"credentialSubject": 321,
					},
				},
			},
			want:  321,
			want1: true,
		},
		{
			name: "error - vc root claim does not exist",
			args: args{
				key: "credentialSubject",
				claims: map[string]interface{}{
					"some": map[string]interface{}{
						"credentialSubject": 321,
					},
				},
			},
			want:  nil,
			want1: false,
		},
		{
			name: "error - vc root claim exist but not a map",
			args: args{
				key: "credentialSubject",
				claims: map[string]interface{}{
					"vc": 123,
				},
			},
			want:  nil,
			want1: false,
		},
		{
			name: "error - vc root claim exist but key does not exist in nested map",
			args: args{
				key: "credentialSubject",
				claims: map[string]interface{}{
					"vc": map[string]interface{}{
						"some": 321,
					},
				},
			},
			want:  nil,
			want1: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := GetKeyFromVC(tt.args.key, tt.args.claims)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetKeyFromVC() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetKeyFromVC() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestGetDisclosureDigests(t *testing.T) {
	type args struct {
		claims map[string]interface{}
	}

	tests := []struct {
		name    string
		args    args
		want    map[string]bool
		wantErr bool
	}{
		{
			name: "success - sd and array elements",
			args: args{
				claims: map[string]interface{}{
					SDKey: []string{
						"digest1", "digest2",
					},
					"claim1": []interface{}{
						map[string]interface{}{
							ArrayElementDigestKey: "digest3",
						},
					},
				},
			},
			want: map[string]bool{
				"digest1": true,
				"digest2": true,
				"digest3": true,
			},
			wantErr: false,
		},
		{
			name: "success - sd root and nested claims",
			args: args{
				claims: map[string]interface{}{
					SDKey: []string{
						"digest1", "digest2",
					},
					"claim1": map[string]interface{}{
						SDKey: []string{
							"digest3",
						},
					},
				},
			},
			want: map[string]bool{
				"digest1": true,
				"digest2": true,
			},
			wantErr: false,
		},
		{
			name: "success - array element on nested level",
			args: args{
				claims: map[string]interface{}{
					"claim1": map[string]interface{}{
						"claim2": map[string]interface{}{
							ArrayElementDigestKey: "digest3",
						},
					},
				},
			},
			want:    map[string]bool{},
			wantErr: false,
		},
		{
			name: "success - array element not a string",
			args: args{
				claims: map[string]interface{}{
					"claim1": []interface{}{
						map[string]interface{}{
							ArrayElementDigestKey: 123,
						},
					},
				},
			},
			want:    map[string]bool{},
			wantErr: false,
		},
		{
			name: "success - array element map longer then one",
			args: args{
				claims: map[string]interface{}{
					"claim1": []interface{}{
						map[string]interface{}{
							ArrayElementDigestKey: "digest3",
							"claim2":              "digest4",
						},
					},
				},
			},
			want:    map[string]bool{},
			wantErr: false,
		},
		{
			name: "success - array element is not a map",
			args: args{
				claims: map[string]interface{}{
					"claim1": []interface{}{"digest3"},
				},
			},
			want:    map[string]bool{},
			wantErr: false,
		},
		{
			name: "success - no array and sd elements",
			args: args{
				claims: map[string]interface{}{
					"claim1": map[string]interface{}{
						"claim2": []interface{}{"claim3"},
					},
				},
			},
			want:    map[string]bool{},
			wantErr: false,
		},
		{
			name: "error - sd element is not a string",
			args: args{
				claims: map[string]interface{}{
					SDKey: []int{123},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetDisclosureDigests(tt.args.claims)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDisclosureDigests() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetDisclosureDigests() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func printObject(t *testing.T, name string, obj interface{}) {
	t.Helper()

	objBytes, err := json.Marshal(obj)
	require.NoError(t, err)

	prettyJSON, err := prettyPrint(objBytes)
	require.NoError(t, err)

	fmt.Println(name + ":")
	fmt.Println(prettyJSON)
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

type NoopSignatureVerifier struct {
}

func (sv *NoopSignatureVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return nil
}

const additionalSDDisclosure = `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0`
const additionalArrayElementDisclosure = `WyJjc3AteWZLWWNTYWlkUElUMHpyOFNRIiwiTWluYXMgVGlyaXRoIl0`

const testCombinedFormatForIssuance = `eyJhbGciOiJFZERTQSJ9.eyJfc2QiOlsicXF2Y3FuY3pBTWdZeDdFeWtJNnd3dHNweXZ5dks3OTBnZTdNQmJRLU51cyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImV4cCI6MTcwMzAyMzg1NSwiaWF0IjoxNjcxNDg3ODU1LCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsIm5iZiI6MTY3MTQ4Nzg1NX0.vscuzfwcHGi04pWtJCadc4iDELug6NH6YK-qxhY1qacsciIHuoLELAfon1tGamHtuu8TSs6OjtLk3lHE16jqAQ~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           // nolint: lll
const testCombinedFormatForIssuanceV5 = `eyJhbGciOiJFZERTQSJ9.eyJfc2RfYWxnIjoic2hhLTI1NiIsImFkZHJlc3MiOnsiX3NkIjpbIlRaV0JRdlpTam1VemxRZ1AzZ2EydkFlYlV6cDhpU2NRNlBFT0gzSHQ1bm8iXSwiY2l0aWVzIjpbeyIuLi4iOiI0U1lCT3NMcVRURU42QnpTSV9NX0pyQ0NzWFJ0Y1BTbWNqV3ROMEdjU0dJIn0sIkVsIFBhc28iXSwiY291bnRyeUNvZGVzIjpbeyIuLi4iOiJab2hsNGd4OXd0czJBRlVrbmd1c3FleWJDUERWUVFLNHNPR3A4dWZHcWg4In0seyIuLi4iOiIxbVl4V1VZN2M5T1pEWlZnd0N6aUFuWkY1TDgzUzZaN2pGb1U2ck5vaEtzIn1dLCJleHRyYSI6eyJfc2QiOlsibXZtZVoxb3ZmY1RRTi01Q3A5YlhYcElKREd2THVkNVg4SVIyajctVUd0WSJdfSwicmVnaW9uIjoiU2FjaHNlbi1BbmhhbHQifSwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIifQ.l-xc_9hGQMHfkPmMeG_EQIZU5guVme9FSKgN58WqfBJcMvfrb9rTc2PHmxveerMTA2cjgJzM2OZgibQCxRePAg~WyJTUEh2T185NEsyWENVdVhSeURjcHJnIiwibG9jYWxpdHkiLCJTY2h1bHBmb3J0YSJd~WyJSaHh1bDBnd2x6cTlSNDg4ZV8tQ3B3IiwiVUEiXQ~WyJKQWlwWm5uSUM3ejAtZzJoNzZmc0FBIiwiUEwiXQ~WyIxdzZVNkRkSG9laFdUdG5UNG5iS3RnIiwiQWxidXF1ZXJxdWUiXQ~WyJVWnUxcjR5YnpfUGNiU3BRcTFpMllRIiwicmVjdXJzaXZlIix7Il9zZCI6WyJydjZNejBheXJZYWU1MHpWRXYtbExKNFZRRzhNMGFJdjJOVW1LVDRRRjVJIl19XQ~WyJoRWNiQmxZQ0ZSVGVtMG1uVXQzTVNnIiwia2V5MSIsInZhbHVlMSJd` // nolint: lll

// nolint: lll
const testSDJWT = `eyJhbGciOiJFZERTQSJ9.eyJfc2QiOlsicXF2Y3FuY3pBTWdZeDdFeWtJNnd3dHNweXZ5dks3OTBnZTdNQmJRLU51cyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImV4cCI6MTcwMzAyMzg1NSwiaWF0IjoxNjcxNDg3ODU1LCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsIm5iZiI6MTY3MTQ4Nzg1NX0.vscuzfwcHGi04pWtJCadc4iDELug6NH6YK-qxhY1qacsciIHuoLELAfon1tGamHtuu8TSs6OjtLk3lHE16jqAQ`

// nolint: lll
const specCombinedFormatForIssuance = `eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJfc2QiOiBbIk5ZQ29TUktFWXdYZHBlNXlkdUpYQ3h4aHluRVU4ei1iNFR5TmlhcDc3VVkiLCAiU1k4bjJCYmtYOWxyWTNleEhsU3dQUkZYb0QwOUdGOGE5Q1BPLUc4ajIwOCIsICJUUHNHTlBZQTQ2d21CeGZ2MnpuT0poZmRvTjVZMUdrZXpicGFHWkNUMWFjIiwgIlprU0p4eGVHbHVJZFlCYjdDcWtaYkpWbTB3MlY1VXJSZU5UekFRQ1lCanciLCAibDlxSUo5SlRRd0xHN09MRUlDVEZCVnhtQXJ3OFBqeTY1ZEQ2bXRRVkc1YyIsICJvMVNBc0ozM1lNaW9POXBYNVZlQU0xbHh1SEY2aFpXMmtHZGtLS0JuVmxvIiwgInFxdmNxbmN6QU1nWXg3RXlrSTZ3d3RzcHl2eXZLNzkwZ2U3TUJiUS1OdXMiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNTE2MjM5MDIyLCAiZXhwIjogMTUxNjI0NzAyMiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDhaZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1UW9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkwwRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTRxUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifX19.xqgKrDO6dK_oBL3fiqdcq_elaIGxM6Z-RyuysglGyddR1O1IiE3mIk8kCpoqcRLR88opkVWN2392K_XYfAuAmeT9kJVisD8ZcgNcv-MQlWW9s8WaViXxBRe7EZWkWRQcQVR6jf95XZ5H2-_KA54POq3L42xjk0y5vDr8yc08Reak6vvJVvjXpp-Wk6uxsdEEAKFspt_EYIvISFJhfTuQqyhCjnaW13X312MSQBPwjbHn74ylUqVLljDvqcemxeqjh42KWJq4C3RqNJ7anA2i3FU1kB4-KNZWsijY7-op49iL7BrnIBxdlAMrbHEkoGTbFWdl7Ki17GHtDxxa1jaxQg~WyJkcVR2WE14UzBHYTNEb2FHbmU5eDBRIiwgInN1YiIsICJqb2huX2RvZV80MiJd~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJxUVdtakpsMXMxUjRscWhFTkxScnJ3IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJLVXhTNWhFX1hiVmFjckdBYzdFRnd3IiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyIzcXZWSjFCQURwSERTUzkzOVEtUml3IiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyIweEd6bjNNaXFzY3RaSV9PcERsQWJRIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJFUktNMENOZUZKa2FENW1UWFZfWDh3IiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0`

// Payload represents JWT payload.
type payload struct {
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`

	SDAlg string `json:"_sd_alg,omitempty"`
}

const specExample2bJWT = `eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIjBsa1NjS2ppSk1IZWRKZnE3c0pCN0hRM3FvbUdmckVMYm81Z1podktSV28iLCAiMWgyOWdnUWkxeG91LV9OalZ5eW9DaEsyYXN3VXRvMlVqQ2ZGLTFMYWhBOCIsICIzQ29MVUxtRHh4VXdfTGR5WUVUanVkdVh1RXBHdUJ5NHJYSG90dUQ0MFg0IiwgIkFJRHlveHgxaXB5NDUtR0ZwS2d2Yy1ISWJjVnJsTGxyWUxYbXgzZXYyZTQiLCAiT2x0aGZSb0ZkUy1KNlM4Mk9XbHJPNHBXaG9lUk1ySF9LR1BfaDZFYXBZUSIsICJyNGRicEdlZWlhMDJTeUdMNWdCZEhZMXc4SWhqVDN4eDA1UnNmeXlIVWs0Il0sICJhZGRyZXNzIjogeyJfc2QiOiBbIjZPS053bkdHS1dYQ0k5dWlqTkFzdjY0dTIyZUxTNHJNZExObGcxZnFKcDQiLCAiSEVWTWdELU5LSzVOdlhQYkFSb3JWZE9ESVRta1V5dU1wQ3NfbTdIWG5ZYyIsICJVcTAyblY3M0swYmRSSzIzcnphYm1uRGE0TzhZTlFadnQ5eDhMeWtva19ZIiwgIm94RlJpbG5vMjZVWWU3a3FNTTRiZHE4SXZOTXRJaTZGOHB0dC11aVBMYk0iXX0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTUxNjIzOTAyMiwgImV4cCI6IDE1MTYyNDcwMjIsICJfc2RfYWxnIjogInNoYS0yNTYifQ.M45AUExpi9THOTVIHfBmb2GL0WXJf4TeWB5QPmsxdBkj9pUcLOPR8YVafLIt8m_imYHTBYYcAyf7qSnquxMxGQ` // nolint:lll
const specExample2bDisclosures = `~WyJSdHczZUFFUE5wWjIwTkhZSzNNRWNnIiwgImZhbWlseV9uYW1lIiwgIlx1NWM3MVx1NzUzMCJd~WyJicjgxenVSc0NUcXJuWEp4MHVqMkRRIiwgImdpdmVuX25hbWUiLCAiXHU1OTJhXHU5MGNlIl0~WyI1Z2NXRmxWSEM1VVEwbktrallybDlnIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJJTms2bkx4WGFybDF4NmVabHdBOTV3IiwgImVtYWlsIiwgIlwidW51c3VhbCBlbWFpbCBhZGRyZXNzXCJAbmlob24uY29tIl0~WyJNOVY2N3V0UC1hTF9lR1B0UU5hM0RRIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ~WyJzNFhNSmxXQ2Eza3hDWk4wSVVrbnlBIiwgImNvdW50cnkiLCAiSlAiXQ~`                                                                                                                                                                                                                                                                                                                                                                                                                                                             // nolint:lll

const vcSample = `
{
	"iat": 1673987547,
	"iss": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	"jti": "http://example.edu/credentials/1872",
	"nbf": 1673987547,
	"sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	"vc": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1"
		],
		"credentialSubject": {
			"_sd": [
				"GJFkje8c1iayy1HQW__JEhuHTz8QGlkcMaxDTjT1wpQ",
				"goPn0hokFnQBktqzXxgTK-4CCldmLjlRwUVCIltDyRg",
				"FAiNODIxDMwGTljNYcVKkx7LBsr1pb-U6XuAfVFuOGY"
			],
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"
		},
		"_sd_alg": "sha-256",
		"cnf": {
			"jwk": {
				"crv": "Ed25519",
				"kty": "OKP",
				"x": "7jtkxxk0Pb3E0O6JXJiN8HyIp2DpCiqaHCWfMXl9ZFo"
			}
		},
		"first_name": "First name",
		"id": "http://example.edu/credentials/1872",
		"info": "Info",
		"issuanceDate": "2023-01-17T22:32:27.468109817+02:00",
		"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		"last_name": "Last name",
		"type": "VerifiableCredential"
	}
}`
