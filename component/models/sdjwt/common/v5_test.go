package common

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetClaimsV5(t *testing.T) {
	t.Run("full disclosures", func(t *testing.T) {
		testDisclosures := `[
	"WyI2NDYwRkU1STJvN0l0bktGX2s4YWZ3IiwiYWRkcmVzcyIseyJfc2QiOlsiQjJBQVFzTVk4V1B1bWZoOWtXY3J1RXV4TUVaT2J5bW5MNGU2OVB5U0psNCIsIkV3TGVJbVFVdWIyS1F6eURoNmxnU1c1TnZsMExqQWFlaXFCZHJzeDY1T28iLCI4TG56SUJ5QlNDZ243SG1zcURUbW1GeXZSVTRRdHRuaVNlZE4xanN2LXhvIiwibk54dThkU3laV0x3QVAteTJtV0k5aXRpMmRHejQ5RUM0eDY2RGxDZ0QwZyJdLCJleHRyYSI6eyJfc2QiOlsib2RqUjRraHQxcGVNZFRUMzVFMUotWXF5Q0gyM0dfSGhrQXRLZks0cUpIVSJdfSwiZXh0cmFBcnJJbmNsdWRlIjpbeyIuLi4iOiIxRVN5RGlLTE9KbEF2VnYtQnJaN1JQTU4zRXVOdU1Jc014aXVMeGhZWjg0In0sIlBMIl0sInJlZ2lvbiI6IlNhY2hzZW4tQW5oYWx0In1d",
	"WyJZbEFCTmZkaXhKSVF4Z3hNZ0RTcUpRIiwiY291bnRyeSIsIkRFIl0",
	"WyJJdGZ2ellZdXlMSTF3TGZLU213M0dRIiwiZXh0cmFBcnIiLFt7Ii4uLiI6IkRsVHpXT0tWbzJNbzNPNUZER0hpWGhuSnd4c2hBTkQyMUVibmQyWFRiT0kifSx7Ii4uLiI6IkMwbUl4SXdEQm4xZ1IxamZBTDFYZVJNdGlYLVdDMVBjc3FUVkphdnJMQTQifV1d",
	"WyJkWW10LWNjcWMyeUJYd1ZGTFZkeFdnIiwic3RyZWV0X2FkZHJlc3MiLCJTY2h1bHN0ci4gMTIiXQ",
	"WyJURWtwSjJkYWxraGltUUVLd25Cblp3IiwiVUEiXQ",
	"WyIxRTlRZnRDS3YtbTFjN0VFOXlXMmh3IiwiRXh0cmExIl0",
	"WyI0Mjl4ejFGeTlEdU9SQ0R2cHd3bzFBIiwiRXh0cmEyIl0",
	"WyJvVy1oMDZYVUNsTU45YTBVV3VHMGhBIiwicmVjdXJzaXZlIix7Il9zZCI6WyJoX2h1bVhsYjhVekM5T0tGOHc3SEd6ZmYzSGgzMmh3SGR6Vms5WS1oOGR3Il19XQ",
	"WyItdHBPTUlPS3dnOUNtNlBRVTlDTktBIiwia2V5MSIsInZhbHVlMSJd",
	"WyJ5WElBaTZSb1Y1eDV2X3lsVm1wXzhBIiwibG9jYWxpdHkiLCJTY2h1bHBmb3J0YSJd"
]`

		var disData []string
		assert.NoError(t, json.Unmarshal([]byte(testDisclosures), &disData))

		parsed, err := GetDisclosureClaims(disData, crypto.SHA256)
		assert.NoError(t, err)
		assert.Len(t, parsed, 7)

		var address *DisclosureClaim
		for _, cl := range parsed {
			if cl.Name == "address" {
				address = cl
				break
			}
		}

		assert.Equal(t, map[string]interface{}{
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

	t.Run("array element and one value missing", func(t *testing.T) {
		testDisclosures := `[
	"WyI2NDYwRkU1STJvN0l0bktGX2s4YWZ3IiwiYWRkcmVzcyIseyJfc2QiOlsiQjJBQVFzTVk4V1B1bWZoOWtXY3J1RXV4TUVaT2J5bW5MNGU2OVB5U0psNCIsIkV3TGVJbVFVdWIyS1F6eURoNmxnU1c1TnZsMExqQWFlaXFCZHJzeDY1T28iLCI4TG56SUJ5QlNDZ243SG1zcURUbW1GeXZSVTRRdHRuaVNlZE4xanN2LXhvIiwibk54dThkU3laV0x3QVAteTJtV0k5aXRpMmRHejQ5RUM0eDY2RGxDZ0QwZyJdLCJleHRyYSI6eyJfc2QiOlsib2RqUjRraHQxcGVNZFRUMzVFMUotWXF5Q0gyM0dfSGhrQXRLZks0cUpIVSJdfSwiZXh0cmFBcnJJbmNsdWRlIjpbeyIuLi4iOiIxRVN5RGlLTE9KbEF2VnYtQnJaN1JQTU4zRXVOdU1Jc014aXVMeGhZWjg0In0sIlBMIl0sInJlZ2lvbiI6IlNhY2hzZW4tQW5oYWx0In1d",
	"WyJZbEFCTmZkaXhKSVF4Z3hNZ0RTcUpRIiwiY291bnRyeSIsIkRFIl0",
	"WyJJdGZ2ellZdXlMSTF3TGZLU213M0dRIiwiZXh0cmFBcnIiLFt7Ii4uLiI6IkRsVHpXT0tWbzJNbzNPNUZER0hpWGhuSnd4c2hBTkQyMUVibmQyWFRiT0kifSx7Ii4uLiI6IkMwbUl4SXdEQm4xZ1IxamZBTDFYZVJNdGlYLVdDMVBjc3FUVkphdnJMQTQifV1d",
	"WyJkWW10LWNjcWMyeUJYd1ZGTFZkeFdnIiwic3RyZWV0X2FkZHJlc3MiLCJTY2h1bHN0ci4gMTIiXQ",
	"WyIxRTlRZnRDS3YtbTFjN0VFOXlXMmh3IiwiRXh0cmExIl0",
	"WyI0Mjl4ejFGeTlEdU9SQ0R2cHd3bzFBIiwiRXh0cmEyIl0",
	"WyJvVy1oMDZYVUNsTU45YTBVV3VHMGhBIiwicmVjdXJzaXZlIix7Il9zZCI6WyJoX2h1bVhsYjhVekM5T0tGOHc3SEd6ZmYzSGgzMmh3SGR6Vms5WS1oOGR3Il19XQ",
	"WyItdHBPTUlPS3dnOUNtNlBRVTlDTktBIiwia2V5MSIsInZhbHVlMSJd"
]`

		// - 	"WyJ5WElBaTZSb1Y1eDV2X3lsVm1wXzhBIiwibG9jYWxpdHkiLCJTY2h1bHBmb3J0YSJd" locality
		// - 	"WyJURWtwSjJkYWxraGltUUVLd25Cblp3IiwiVUEiXQ", UA
		var disData []string
		assert.NoError(t, json.Unmarshal([]byte(testDisclosures), &disData))
		parsed, err := GetDisclosureClaims(disData, crypto.SHA256)
		assert.NoError(t, err)
		assert.Len(t, parsed, 6) // - locality - arr elements

		var address *DisclosureClaim
		for _, cl := range parsed {
			if cl.Name == "address" {
				address = cl
				break
			}
		}

		assert.Equal(t, map[string]interface{}{
			"_sd": []interface{}{
				"8LnzIByBSCgn7HmsqDTmmFyvRU4QttniSedN1jsv-xo", // locality
			},
			"extraArrInclude": []interface{}{
				map[string]interface{}{
					"...": "1ESyDiKLOJlAvVv-BrZ7RPMN3EuNuMIsMxiuLxhYZ84", // UA
				},
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
}
