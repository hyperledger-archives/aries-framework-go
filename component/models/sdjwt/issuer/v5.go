package issuer

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"

	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

type SDJWTBuilderV5 struct {
}

func (s *SDJWTBuilderV5) keysToExclude() []string {
	return []string{
		"iss",
		"iat",
		"nbf",
		"exp",
		"cnf",
		"type",
		"status",
		"sub",
	}
}

func NewSDJWTBuilderV5() *SDJWTBuilderV5 {
	return &SDJWTBuilderV5{}
}

func (s *SDJWTBuilderV5) isAlwaysInclude(curPath string, opts *newOpts) bool {
	if opts == nil || len(opts.alwaysInclude) == 0 {
		return false
	}

	_, ok := opts.alwaysInclude[curPath]
	return ok
}

func (s *SDJWTBuilderV5) isIgnored(curPath string, opts *newOpts) bool {
	if opts == nil || len(opts.nonSDClaimsMap) == 0 {
		return false
	}

	_, ok := opts.nonSDClaimsMap[curPath]
	return ok
}

func (s *SDJWTBuilderV5) isRecursive(curPath string, opts *newOpts) bool {
	if opts == nil || len(opts.recursiveClaimMap) == 0 {
		return false
	}

	_, ok := opts.recursiveClaimMap[curPath]
	return ok
}

func (s *SDJWTBuilderV5) extractValueOptions(curPath string, opts *newOpts) valueOption {
	return valueOption{
		IsStructured:    opts.structuredClaims,
		IsAlwaysInclude: s.isAlwaysInclude(curPath, opts),
		IsIgnored:       s.isIgnored(curPath, opts),
		IsRecursive:     s.isIgnored(curPath, opts),
	}
}

type valueOption struct {
	IsStructured    bool
	IsAlwaysInclude bool
	IsIgnored       bool
	IsRecursive     bool
}

func (s *SDJWTBuilderV5) CreateDisclosuresAndDigests(
	path string,
	claims map[string]interface{},
	opts *newOpts,
) ([]string, map[string]interface{}, error) {
	digestsMap := map[string]interface{}{}
	//var disclosures []string
	//var rootLevelDisclosures []string
	//var arrDisclosures []string
	//digestsMap := make(map[string]interface{})

	finalSDDigest, err := createDecoyDisclosures(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create decoy disclosures: %w", err)
	}

	//var allDisclosures []string
	for key, value := range claims {
		curPath := key
		if path != "" {
			curPath = path + "." + key
		}

		kind := reflect.TypeOf(value).Kind()

		valOption := s.extractValueOptions(curPath, opts)
		switch kind {
		case reflect.Map:
			if valOption.IsIgnored {
				digestsMap[key] = value
			} else if valOption.IsRecursive {

			} else if valOption.IsAlwaysInclude || valOption.IsStructured {

			} else { // plain

			}
		case reflect.Array:
			fallthrough
		case reflect.Slice:
			if valOption.IsIgnored { // whole array ignored
				digestsMap[key] = value
				continue
			}

			elementsDigest, elementsDisclosures, arrayElemErr := s.processArrayElements(value, curPath, opts)
			if arrayElemErr != nil {
				return nil, nil, arrayElemErr
			}

			if valOption.IsAlwaysInclude || valOption.IsStructured {
				digestsMap[key] = elementsDigest
			} else { // plain
				disclosure, disErr := s.createDisclosure(key, value, opts)
				if disErr != nil {
					return nil, nil, fmt.Errorf("create disclosure for whole err with path [%v]: %w",
						path, disErr)
				}

				finalSDDigest = append(finalSDDigest, disclosure)
			}

			finalSDDigest = append(finalSDDigest, elementsDisclosures...)
		}
		//if kind == reflect.Map && opts.structuredClaims {
		//	// todo
		//	//nestedDisclosures, nestedDigestsMap, e := s.CreateDisclosuresAndDigests(curPath,
		//	//	value.(map[string]interface{}), opts)
		//	//if e != nil {
		//	//	return nil, nil, e
		//	//}
		//
		//	//digestsMap[key] = nestedDigestsMap
		//
		//	//disclosures = append(disclosures, nestedDisclosures...)
		//} else if kind == reflect.Array || kind == reflect.Slice {
		//
		//} else {
		//	if _, ok := opts.nonSDClaimsMap[curPath]; ok {
		//		//digestsMap[key] = value
		//
		//		continue
		//	}
		//
		//	disclosure, e := s.createDisclosure(key, value, opts)
		//	if e != nil {
		//		return nil, nil, fmt.Errorf("create disclosure: %w", e)
		//	}
		//
		//	finalSDDigest = append(finalSDDigest, disclosure)
		//	allDisclosures = append(allDisclosures, disclosure)
		//	//rootLevelDisclosures = append(rootLevelDisclosures, disclosure)
		//}
	}

	//disclosures = append(disclosures, rootLevelDisclosures...)

	digests, err := createDigests(finalSDDigest, opts)
	if err != nil {
		return nil, nil, err
	}

	digestsMap[common.SDKey] = digests

	return finalSDDigest, digestsMap, nil
}

func (s *SDJWTBuilderV5) processArrayElements(
	value interface{},
	path string,
	opts *newOpts,
) ([]interface{}, []string, error) {
	valSl := reflect.ValueOf(value)
	var digestArr []interface{}
	var elementsDisclosures []string
	for i := 0; i < valSl.Len(); i++ {
		elementPath := fmt.Sprintf("%v[%v]", path, i)
		elementOptions := s.extractValueOptions(elementPath, opts)
		elementValue := valSl.Index(i).Interface()

		if elementOptions.IsIgnored {
			digestArr = append(digestArr, elementValue)
			continue
		}

		digest, err := s.createDisclosure("", elementValue, opts)
		if err != nil {
			return nil, nil,
				fmt.Errorf("create element disclosure for path [%v]: %w", elementPath, err)
		}
		elementsDisclosures = append(elementsDisclosures, digest)
		digestArr = append(digestArr, map[string]string{"...": digest})
	}

	return digestArr, elementsDisclosures, nil
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

func (s *SDJWTBuilderV5) ExtractCredentialClaims(vcClaims map[string]interface{}) (map[string]interface{}, error) {
	vc, ok := vcClaims[vcKey].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid vc claim")
	}

	return vc, nil
}
