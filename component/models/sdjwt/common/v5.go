/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

			if parsed.Type == DisclosureClaimTypeArrayElement {
				continue
			}

			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", digest)
		}
	}

	return nil
}

func (c *commonV5) getDisclosureClaim(disclosure string) (*DisclosureClaim, error) {
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

	return claim, nil
}

func (c *commonV5) GetDisclosureClaims(
	disclosures []string,
) ([]*DisclosureClaim, error) {
	claimMap := map[string]*DisclosureClaim{}

	for _, disclosure := range disclosures {
		claim, err := c.getDisclosureClaim(disclosure)
		if err != nil {
			return nil, err
		}

		claimMap[claim.Disclosure] = claim
	}

	var claims []*DisclosureClaim

	for _, claim := range claimMap {
		switch claim.Type {
		case DisclosureClaimTypeArrayElement:
			continue
		case DisclosureClaimTypeArray:
			sValue := reflect.ValueOf(claim.Value)

			var updatedElements []interface{}

			for i := 0; i < sValue.Len(); i++ {
				key, ok := sValue.Index(i).Interface().(map[string]interface{})
				if !ok {
					return nil, errors.New("cast err for array element")
				}

				disVal, ok := key["..."]
				if !ok {
					return nil, errors.New("... not found in map")
				}

				v, ok := claimMap[fmt.Sprint(disVal)]
				if !ok {
					return nil, fmt.Errorf("array element with key %v not found", key)
				}

				updatedElements = append(updatedElements, v.Value)
			}

			claim.Value = updatedElements

			claims = append(claims, claim)
		default:
			claims = append(claims, claim)
		}
	}

	return claims, nil
}
