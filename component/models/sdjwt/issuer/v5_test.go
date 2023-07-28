package issuer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDisclosureV5Map(t *testing.T) {
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

		resp1, resp2, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			getSalt:     generateSalt,
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			recursiveClaimMap: map[string]bool{
				"address": true,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp1, resp2)
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
			getSalt:     generateSalt,
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
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
func TestDisclosureV5Array(t *testing.T) {
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
			  ]
			}`
		var parsedInput map[string]interface{}
		assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
		bb := NewSDJWTBuilderV5()
		bb.debugMode = true

		resp1, resp2, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			getSalt:     generateSalt,
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			alwaysInclude: map[string]bool{
				"nationalities": true,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp1, resp2)
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

		resp1, resp2, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			getSalt:     generateSalt,
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			nonSDClaimsMap: map[string]bool{
				"nationalities[1]": true,
			},
			alwaysInclude: map[string]bool{
				"nationalities": true,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, resp1, resp2)
	})
}
