package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

type commonV2 struct {
	disclosureParts int
	saltIndex       int
	nameIndex       int
	valueIndex      int
}

func newCommonV2() *commonV2 {
	return &commonV2{
		disclosureParts: 3,
		saltIndex:       0,
		nameIndex:       1,
		valueIndex:      2,
	}
}

// VerifyDisclosuresInSDJWT checks for disclosure inclusion in SD-JWT.
func (c *commonV2) VerifyDisclosuresInSDJWT(disclosures []string, signedJWT *afgjwt.JSONWebToken) error {
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
			return fmt.Errorf("disclosure digest '%s' not found in SD-JWT disclosure digests", digest)
		}
	}

	return nil
}

func (c *commonV2) GetDisclosureClaims(
	disclosures []string,
) ([]*DisclosureClaim, error) {
	var claims []*DisclosureClaim

	for _, disclosure := range disclosures {
		claim, err := c.getDisclosureClaim(disclosure)
		if err != nil {
			return nil, err
		}

		claims = append(claims, claim)
	}

	return claims, nil
}

func (c *commonV2) getDisclosureClaim(disclosure string) (*DisclosureClaim, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
	fmt.Println(string(decoded))
	if err != nil {
		return nil, fmt.Errorf("failed to decode disclosure: %w", err)
	}

	var disclosureArr []interface{}

	err = json.Unmarshal(decoded, &disclosureArr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal disclosure array: %w", err)
	}

	if len(disclosureArr) != c.disclosureParts {
		return nil, fmt.Errorf("disclosure array size[%d] must be %d", len(disclosureArr), c.disclosureParts)
	}

	salt, ok := disclosureArr[c.saltIndex].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure salt type[%T] must be string", disclosureArr[c.saltIndex])
	}

	name, ok := disclosureArr[c.nameIndex].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure name type[%T] must be string", disclosureArr[c.nameIndex])
	}

	claim := &DisclosureClaim{Disclosure: disclosure, Salt: salt, Name: name, Value: disclosureArr[c.valueIndex]}

	return claim, nil
}
