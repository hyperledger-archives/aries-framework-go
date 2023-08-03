/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/exp/slices"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func VerifyDisclosuresInSDJWT(
	disclosures []string,
	signedJWT *afgjwt.JSONWebToken,
) error {
	claims := utils.CopyMap(signedJWT.Payload)
	cryptoHash, err := GetCryptoHashFromClaims(claims)
	if err != nil {
		return err
	}

	recData, err := getDisclosureClaimsInternal(
		disclosures,
		cryptoHash,
		false,
	) // we don`t need to change values for now.
	if err != nil {
		return err
	}

	_, err = processObj(claims, recData) // now lets extract _sd and arrays from claims.
	if err != nil {
		return err
	}

	for _, claim := range recData.claimMap {
		if !slices.Contains(recData.foundSDs, claim.Digest) {
			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", claim.Digest)
		}
	}

	return nil
}

func getDisclosureClaim(disclosure string, hash crypto.Hash) (*wrappedClaim, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosure: %w", err)
	}

	var disclosureArr []interface{}

	err = json.Unmarshal(decoded, &disclosureArr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal disclosure array: %w", err)
	}

	if len(disclosureArr) < 2 {
		return nil, fmt.Errorf("disclosure array size[%d] must be greater %d", len(disclosureArr),
			2)
	}

	claim := &DisclosureClaim{Disclosure: disclosure}

	salt, ok := disclosureArr[0].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure salt type[%T] must be string", disclosureArr[1])
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

		switch disclosureArr[2].(type) {
		case map[string]interface{}:
			claim.Type = DisclosureClaimTypeObject
		default:
			claim.Type = DisclosureClaimTypePlainText
		}
	}

	digest, err := GetHash(hash, disclosure)
	if err != nil {
		return nil, fmt.Errorf("get disclosure hash: %w", err)
	}

	return &wrappedClaim{
		Claim:         claim,
		IsValueParsed: false,
		Digest:        digest,
	}, nil
}

func processClaimValue(
	recData *recursiveData,
	claim *wrappedClaim,
) error {
	if claim.IsValueParsed {
		return nil
	}

	v, err := processObj(claim.Claim.Value, recData)
	if err != nil {
		return err
	}

	claim.Claim.Value = v
	claim.IsValueParsed = true

	return nil
}

func processObj(
	inputObj interface{},
	recData *recursiveData,
) (interface{}, error) {
	switch obj := inputObj.(type) {
	case []interface{}:
		var newValues []interface{}
		for _, element := range obj {
			parsedMap, ok := element.(map[string]interface{})
			if !ok {
				newValues = append(newValues, element)
				continue
			}

			elementDigest, ok := parsedMap[ArrayElementDigestKey]
			if !ok {
				return nil, errors.New("invalid array struct")
			}

			elementStr := fmt.Sprint(elementDigest)
			if !slices.Contains(recData.foundSDs, elementStr) {
				recData.foundSDs = append(recData.foundSDs, elementStr)
			}
			cl, ok := recData.claimMap[elementStr]
			if !ok {
				newValues = append(newValues, element)
				continue
			}

			if err := processClaimValue(recData, cl); err != nil {
				return nil, err
			}

			newValues = append(newValues, cl.Claim.Value)
		}

		return newValues, nil
	case map[string]interface{}:
		for k, v := range obj {
			if k == SDKey {
				continue
			}

			res, resErr := processObj(v, recData)
			if resErr != nil {
				return nil, resErr
			}
			if recData.modifyValues {
				obj[k] = res
			}
		}
		if sd, sdOk := obj[SDKey]; sdOk {
			sdArr, sdErr := stringArray(sd)
			if sdErr != nil {
				return nil, fmt.Errorf("get disclosure digests: %w", sdErr)
			}

			var missingSDs []interface{}
			for _, sdElement := range sdArr {
				elementStr := fmt.Sprint(sdElement)
				if !slices.Contains(recData.foundSDs, elementStr) {
					recData.foundSDs = append(recData.foundSDs, elementStr)
				}

				cl, clOk := recData.claimMap[elementStr]
				if !clOk {
					missingSDs = append(missingSDs, sdElement)
					continue
				}

				if err := processClaimValue(recData, cl); err != nil {
					return nil, err
				}

				if recData.modifyValues {
					obj[cl.Claim.Name] = cl.Claim.Value
				}
			}

			if recData.modifyValues {
				delete(obj, SDKey)
				if len(missingSDs) > 0 {
					obj[SDKey] = missingSDs
				}
			}
		}

		return obj, nil
	default:
		return inputObj, nil
	}
}

func getDisclosureClaimsInternal(
	disclosures []string,
	hash crypto.Hash,
	modifyValues bool,
) (*recursiveData, error) {
	claimMap := map[string]*wrappedClaim{}

	for _, disclosure := range disclosures {
		claim, err := getDisclosureClaim(disclosure, hash)
		if err != nil {
			return nil, err
		}

		claimMap[claim.Digest] = claim
	}

	recData := &recursiveData{
		claimMap:     claimMap,
		modifyValues: modifyValues,
	}

	for _, v := range claimMap {
		if err := processClaimValue(recData, v); err != nil {
			return nil, err
		}
	}

	return recData, nil
}
