/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

type commonV5 struct {
	disclosureParts int
	saltIndex       int
}

func newCommonV5() *commonV5 {
	return &commonV5{
		disclosureParts: 2,
		saltIndex:       0,
	}
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func (c *commonV5) VerifyDisclosuresInSDJWT(disclosures []string, signedJWT *afgjwt.JSONWebToken) error {
	claims := utils.CopyMap(signedJWT.Payload)

	// check that the _sd_alg claim is present
	// check that _sd_alg value is understood and the hash algorithm is deemed secure.
	cryptoHash, err := GetCryptoHashFromClaims(claims)
	if err != nil {
		return err
	}

	for _, disclosure := range disclosures {
		digest, err := GetHash(cryptoHash, disclosure)
		if err != nil {
			return err
		}

		found, err := isDigestInClaims(digest, claims)
		if err != nil {
			return err
		}

		if !found {
			parsed, err := c.getDisclosureClaim(disclosure)
			if err != nil {
				return err
			}

			if parsed.Claim.Type == DisclosureClaimTypeArrayElement {
				continue
			}

			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", digest)
		}
	}

	return nil
}

func (c *commonV5) getDisclosureClaim(disclosure string) (*wrappedClaim, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosure: %w", err)
	}

	var disclosureArr []interface{}

	err = json.Unmarshal(decoded, &disclosureArr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal disclosure array: %w", err)
	}

	if len(disclosureArr) < c.disclosureParts {
		return nil, fmt.Errorf("disclosure array size[%d] must be greater %d", len(disclosureArr),
			c.disclosureParts)
	}

	claim := &DisclosureClaim{Disclosure: disclosure}

	salt, ok := disclosureArr[c.saltIndex].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure salt type[%T] must be string", disclosureArr[c.saltIndex])
	}

	claim.Salt = salt

	if len(disclosureArr) == 2 { // array
		claim.Value = disclosureArr[1]
		claim.Type = DisclosureClaimTypeArrayElement
	} else {
		name, ok := disclosureArr[1].(string)
		if !ok {
			return nil, fmt.Errorf("disclosure name type[%T] must be string", disclosureArr[1])
		}

		claim.Name = name
		claim.Value = disclosureArr[2]

		switch reflect.TypeOf(claim.Value).Kind() {
		case reflect.Array:
			fallthrough
		case reflect.Slice:
			claim.Type = DisclosureClaimTypeArray
		}
	}

	digest, err := GetHash(crypto.SHA256, disclosure)
	if err != nil {
		return nil, err
	}

	return &wrappedClaim{
		Claim:         claim,
		IsValueParsed: false,
		Digest:        digest,
	}, nil
}

func (c *commonV5) processClaimValue(
	claimMap map[string]*wrappedClaim,
	claim *wrappedClaim,
) {
	if claim.IsValueParsed {
		return
	}

	claim.Claim.Value = c.processObj(claim.Claim.Value, claimMap)
	claim.IsValueParsed = true
}

func (c *commonV5) processObj(
	inputObj interface{},
	claimMap map[string]*wrappedClaim,
) interface{} {
	switch obj := inputObj.(type) {
	case []interface{}:
		var newValues []interface{}
		for _, element := range obj {
			parsedMap, ok := element.(map[string]interface{})
			if !ok {
				newValues = append(newValues, element)
				continue
			}

			elementDigest, ok := parsedMap["..."]
			if !ok {
				panic("invalid array struct")
			}

			elementVal, ok := elementDigest.(string)
			if !ok {
				panic("invalid element type")
			}

			cl, ok := claimMap[elementVal]
			if !ok {
				panic("digest not found")
			}

			c.processClaimValue(claimMap, cl)

			newValues = append(newValues, cl.Claim.Value)
		}

		return newValues
	case map[string]interface{}:
		for k, v := range obj {
			if k == "_sd" {
				continue
			}

			obj[k] = c.processObj(v, claimMap)
		}
		if sd, sdOk := obj["_sd"]; sdOk {
			sdArr, sdArrOk := sd.([]interface{}) // todo
			if !sdArrOk {
				panic("todo")
			}
			for _, sdElement := range sdArr {
				cl, clOk := claimMap[fmt.Sprint(sdElement)]
				if !clOk {
					panic("digest not found")
				}

				c.processClaimValue(claimMap, cl)
				obj[cl.Claim.Name] = cl.Claim.Value
			}
			delete(obj, "_sd")
		}

		return obj
	default:
		return inputObj
	}

	return nil
}

func (c *commonV5) GetDisclosureClaims(
	disclosures []string,
) ([]*DisclosureClaim, error) {
	claimMap := map[string]*wrappedClaim{}

	for _, disclosure := range disclosures {
		claim, err := c.getDisclosureClaim(disclosure)
		if err != nil {
			return nil, err
		}

		claimMap[claim.Digest] = claim
	}

	var finalClaims []*DisclosureClaim
	for _, v := range claimMap {
		if v.Claim.Type == DisclosureClaimTypeArrayElement {
			continue
		}

		c.processClaimValue(claimMap, v)

		finalClaims = append(finalClaims, v.Claim)
	}

	return finalClaims, nil
}
