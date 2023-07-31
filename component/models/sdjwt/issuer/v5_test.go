package issuer

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestDisclosureV5Map(
	t *testing.T,
) {
	t.Run("recursive", func(t *testing.T) {
		input := `{
		  "address": {
			"street_address": "Schulstr. 12",
			"locality": "Schulpforta",
			"region": "Sachsen-Anhalt",
			"country": "DE"
		  }
}`
		var parsedInput map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
		bb := NewSDJWTBuilderV5()

		disclosures, cred, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			getSalt:     bb.GenerateSalt,
			recursiveClaimMap: map[string]bool{
				"address": true,
			},
		})
		assert.NoError(t, err)

		sort.Slice(disclosures, func(i, j int) bool {
			return disclosures[i].Key < disclosures[j].Key
		})

		assert.Len(t, disclosures, 5)

		for _, dis := range disclosures {
			assert.NotEmpty(t, dis.Salt)
			assert.NotEmpty(t, dis.Result)
		}

		assert.Equal(t, "address", disclosures[0].Key)
		assert.Equal(t, "country", disclosures[1].Key)
		assert.Equal(t, "DE", disclosures[1].Value)
		assert.Equal(t, "locality", disclosures[2].Key)
		assert.Equal(t, "Schulpforta", disclosures[2].Value)
		assert.Equal(t, "region", disclosures[3].Key)
		assert.Equal(t, "Sachsen-Anhalt", disclosures[3].Value)
		assert.Equal(t, "street_address", disclosures[4].Key)
		assert.Equal(t, "Schulstr. 12", disclosures[4].Value)

		recursiveElements := disclosures[0].Value.(map[string]interface{})["_sd"].([]string)
		assert.Len(t, recursiveElements, 4)

		for _, expected := range []string{
			disclosures[1].DebugDigest,
			disclosures[2].DebugDigest,
			disclosures[3].DebugDigest,
			disclosures[4].DebugDigest,
		} {
			assert.True(t, slices.Contains(recursiveElements, expected))
		}
		assert.Len(t, cred, 1)
		sd := cred["_sd"].([]string)
		assert.Len(t, sd, 1)
		assert.Equal(t, disclosures[0].DebugDigest, sd[0])
	})

	t.Run("recursive with array and and include always", func(t *testing.T) {
		input := `{
		  "address": {
			"street_address": "Schulstr. 12",
			"locality": "Schulpforta",
			"region": "Sachsen-Anhalt",
			"country": "DE",
			"extraArrInclude" : ["UA", "PL"],
			"extraArr" : ["Extra1", "Extra2"],
			"extra" : {
				"recursive" : {
					"key1" : "value1"
				}
			}
		  }
}`
		var parsedInput map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
		bb := NewSDJWTBuilderV5()
		bb.debugMode = true

		disclosures, finalMap, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			getSalt:     bb.GenerateSalt,
			alwaysInclude: map[string]bool{
				"address.extraArrInclude": true,
				"address.extra":           true,
			},
			nonSDClaimsMap: map[string]bool{
				"address.extraArrInclude[1]": true,
				"address.region":             true,
			},
			recursiveClaimMap: map[string]bool{
				"address":                 true,
				"address.extra.recursive": true,
			},
		})

		printObject(t, "final credentials", finalMap)
		printObject(t, "disclosures", disclosures)
		assert.NoError(t, err)
	})
}

func TestDisclosureV5Array(
	t *testing.T,
) {
	t.Run("always visible", func(t *testing.T) {
		input := `{
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
			  "visible_map" : {
				"a" : "b"
              }
			}`
		var parsedInput map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
		bb := NewSDJWTBuilderV5()
		bb.debugMode = true

		disclosures, cred, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			getSalt:     bb.GenerateSalt,
			alwaysInclude: map[string]bool{
				"nationalities": true,
				"visible_map":   true,
			},
		})

		assert.NoError(t, err)
		assert.Len(t, disclosures, 11)
		disMap := map[string]*DisclosureEntity{}
		for _, d := range disclosures {
			disMap[d.DebugDigest] = d
		}
		for _, expectedArrayElements := range []string{"DE", "US"} {
			found := false
			for _, d := range disclosures {
				if d.Key != "" { // for array elements key is empty
					continue
				}

				found = d.Value == expectedArrayElements // exact
				if found {
					break
				}
			}

			assert.True(t, found, "element %v not found", expectedArrayElements)
		}

		visibleMapData := cred["visible_map"].(map[string]interface{})["_sd"].([]string)
		assert.Len(t, visibleMapData, 1)

		visibleDisclosure := disMap[visibleMapData[0]]
		assert.Equal(t, "a", visibleDisclosure.Key)
		assert.Equal(t, "b", visibleDisclosure.Value)

		nationalities := cred["nationalities"].([]interface{})
		assert.Len(t, nationalities, 2)

		for i, nat := range nationalities {
			value := nat.(map[string]string)["..."]
			assert.NotEmpty(t, value)

			element := disMap[value]
			assert.Empty(t, element.Key)
			if i == 0 {
				assert.Equal(t, "US", element.Value)
			} else {
				assert.Equal(t, "DE", element.Value)
			}
		}
		assert.NotNil(t, disclosures, cred)
	})

	t.Run("one array element ignored", func(t *testing.T) {
		input := `{
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
		var parsedInput map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
		bb := NewSDJWTBuilderV5()

		disclosures, cred, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			getSalt:     bb.GenerateSalt,
			nonSDClaimsMap: map[string]bool{
				"nationalities[1]": true,
			},
			alwaysInclude: map[string]bool{
				"nationalities": true,
			},
		})
		assert.NoError(t, err)

		disMap := map[string]*DisclosureEntity{}
		for _, d := range disclosures {
			disMap[d.DebugDigest] = d
		}

		assert.Len(t, disclosures, 9)
		assert.Len(t, cred["_sd"].([]string), 8)

		nat := cred["nationalities"].([]interface{})
		assert.Len(t, nat, 2)

		nat1Val := nat[0].(map[string]string)["..."]
		nat2Val := nat[1].(string)

		assert.Equal(t, "DE", nat2Val)
		assert.Equal(t, "US", disMap[nat1Val].Value)
	})

	t.Run("one array element ignored", func(t *testing.T) {
		input := `{
			  "some_map": {
				"a" : "b"
              },
			  "nationalities": [
				"US",
				"DE"
			  ]
			}`
		var parsedInput map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
		bb := NewSDJWTBuilderV5()

		disclosures, cred, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			getSalt:     bb.GenerateSalt,
			nonSDClaimsMap: map[string]bool{
				"some_map":      true,
				"nationalities": true,
			},
		})
		assert.NoError(t, err)

		assert.Len(t, disclosures, 0)
		assert.Len(t, cred, 2)
		assert.Equal(t, map[string]interface{}{
			"a": "b",
		}, cred["some_map"])
		assert.Equal(t, []interface{}{"US", "DE"}, cred["nationalities"].([]interface{}))
		disMap := map[string]*DisclosureEntity{}
		for _, d := range disclosures {
			disMap[d.DebugDigest] = d
		}
	})
}

func TestFailCases(t *testing.T) {
	t.Run("map object", func(t *testing.T) {
		input := `{
			  "some_map": {
				"a" : "b"
              },
			  "nationalities": [
				"US",
				"DE"
			  ]
			}`
		var parsedInput map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
		bb := NewSDJWTBuilderV5()

		disclosures, cred, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			nonSDClaimsMap: map[string]bool{
				"nationalities": true,
			},
		})
		assert.ErrorContains(t, err, "create disclosure for map object []: missing salt function")
		assert.Nil(t, disclosures, cred)
	})
}

func TestExamplesV5(
	t *testing.T,
) {
	t.Run("4a", func(t *testing.T) {
		t.Run("recursive", func(t *testing.T) {
			// https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-example-4a-sd-jwt-based-ver
			// in example they have 3 items in _sd - decoy
			input := `{
  "first_name": "Erika",
  "family_name": "Mustermann",
  "nationalities": [
    "DE"
  ],
  "birth_family_name": "Schmidt",
  "birthdate": "1973-01-01",
  "address": {
    "postal_code": "12345",
    "locality": "Irgendwo",
    "street_address": "Sonnenstrasse 23",
    "country_code": "DE"
  },
  "is_over_18": true,
  "is_over_21": true,
  "is_over_65": false
}`
			var parsedInput map[string]interface{}
			assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
			bb := NewSDJWTBuilderV5()

			disclosures, cred, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
				jsonMarshal: json.Marshal,
				HashAlg:     defaultHash,
				getSalt:     bb.GenerateSalt,
			})
			assert.NoError(t, err)

			assert.Len(t, disclosures, 10)
			assert.Len(t, cred["_sd"].([]string), 9) // -1 for array element
			assert.Len(t, cred, 1)
		})
	})
}