package issuer

import (
	"encoding/base64"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
)

type builder interface {
	CreateDisclosuresAndDigests(
		path string,
		claims map[string]interface{},
		opts *newOpts,
	) ([]*DisclosureEntity, map[string]interface{}, error)
}

func getBuilderByVersion(
	version common.SDJWTVersion,
) builder {
	switch version {
	case common.SDJWTVersionV5:
		return NewSDJWTBuilderV5()
	default:
		return NewSDJWTBuilderV2()
	}
}

type SDJWTBuilderV2 struct {
}

func NewSDJWTBuilderV2() *SDJWTBuilderV2 {
	return &SDJWTBuilderV2{}
}

func (s *SDJWTBuilderV2) CreateDisclosuresAndDigests(
	path string,
	claims map[string]interface{},
	opts *newOpts,
) ([]*DisclosureEntity, map[string]interface{}, error) { // nolint:lll
	var disclosures []*DisclosureEntity

	var levelDisclosures []*DisclosureEntity

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

		if obj, ok := value.(map[string]interface{}); ok && opts.structuredClaims {
			nestedDisclosures, nestedDigestsMap, e := s.CreateDisclosuresAndDigests(curPath, obj, opts)
			if e != nil {
				return nil, nil, e
			}

			digestsMap[key] = nestedDigestsMap

			disclosures = append(disclosures, nestedDisclosures...)
		} else {
			if _, ok := opts.nonSDClaimsMap[curPath]; ok {
				digestsMap[key] = value

				continue
			}

			disclosure, e := s.createDisclosure(key, value, opts)
			if e != nil {
				return nil, nil, fmt.Errorf("create disclosure: %w", e)
			}

			levelDisclosures = append(levelDisclosures, disclosure)
		}
	}

	disclosures = append(disclosures, levelDisclosures...)

	digests, err := createDigests(append(levelDisclosures, decoyDisclosures...), opts)
	if err != nil {
		return nil, nil, err
	}

	digestsMap[common.SDKey] = digests

	return disclosures, digestsMap, nil
}

func (s *SDJWTBuilderV2) createDisclosure(
	key string,
	value interface{},
	opts *newOpts,
) (*DisclosureEntity, error) {
	salt, err := opts.getSalt()
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	disclosure := []interface{}{salt, key, value}

	disclosureBytes, err := opts.jsonMarshal(disclosure)
	if err != nil {
		return nil, fmt.Errorf("marshal disclosure: %w", err)
	}

	return &DisclosureEntity{
		Result: base64.RawURLEncoding.EncodeToString(disclosureBytes),
	}, nil
}
