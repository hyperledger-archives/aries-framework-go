package issuer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDisclosureV5Array(t *testing.T) {
	input := `{
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
	var parsedInput map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(input), &parsedInput))
	bb := NewSDJWTBuilderV5()

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
}
