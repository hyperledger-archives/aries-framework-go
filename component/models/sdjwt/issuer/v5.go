package issuer

import (
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

type SDJWTBuilderV5 struct {
}

func NewSDJWTBuilderV5() *SDJWTBuilderV5 {
	return &SDJWTBuilderV5{}
}

func (s *SDJWTBuilderV5) CreateDisclosuresAndDigests(
	path string,
	claims map[string]interface{},
	opts *newOpts,
) ([]string, map[string]interface{}, error) {
	var disclosures []string

	var rootLevelDisclosures []string

	digestsMap := make(map[string]interface{})

	decoyDisclosures, err := createDecoyDisclosures(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create decoy disclosures: %w", err)
	}

	for key, value := range claims {
		curPath := key
		if path != "" {
			curPath = path + "." + key
		}

		kind := reflect.TypeOf(value).Kind()
		if kind == reflect.Map && opts.structuredClaims {
			nestedDisclosures, nestedDigestsMap, e := s.CreateDisclosuresAndDigests(curPath,
				value.(map[string]interface{}), opts)
			if e != nil {
				return nil, nil, e
			}

			digestsMap[key] = nestedDigestsMap

			disclosures = append(disclosures, nestedDisclosures...)
		} else if kind == reflect.Array || kind == reflect.Slice {
			valSl := reflect.ValueOf(value)
			var digestArr []map[string]string
			for i := 0; i < valSl.Len(); i++ {
				digest, e := s.createDisclosure("", valSl.Index(i).Interface(),
					opts)
				if e != nil {
					return nil, nil, fmt.Errorf("create disclosure: %w", e)
				}

				rootLevelDisclosures = append(rootLevelDisclosures, digest)
				digestArr = append(digestArr, map[string]string{"...": digest})
			}
			digestsMap[key] = digestArr
		} else {
			if _, ok := opts.nonSDClaimsMap[curPath]; ok {
				digestsMap[key] = value

				continue
			}

			disclosure, e := s.createDisclosure(key, value, opts)
			if e != nil {
				return nil, nil, fmt.Errorf("create disclosure: %w", e)
			}

			rootLevelDisclosures = append(rootLevelDisclosures, disclosure)
		}
	}

	disclosures = append(disclosures, rootLevelDisclosures...)

	digests, err := createDigests(append(rootLevelDisclosures, decoyDisclosures...), opts)
	if err != nil {
		return nil, nil, err
	}

	digestsMap[common.SDKey] = digests

	return disclosures, digestsMap, nil
}

func (s *SDJWTBuilderV5) createDisclosure(
	key string,
	value interface{},
	opts *newOpts,
) (string, error) {
	salt, err := opts.getSalt()
	if err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	disclosure := []interface{}{salt}
	if key != "" {
		disclosure = append(disclosure, key)
	}
	disclosure = append(disclosure, value)

	disclosureBytes, err := opts.jsonMarshal(disclosure)
	if err != nil {
		return "", fmt.Errorf("marshal disclosure: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(disclosureBytes), nil
}
