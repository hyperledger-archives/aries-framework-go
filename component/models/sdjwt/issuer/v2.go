package issuer

import (
	"encoding/base64"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
)

type builder interface {
	CreateDisclosuresAndDigests(
		path string,
		claims map[string]interface{},
		opts *newOpts,
	) ([]string, map[string]interface{}, error)

	NewFromVC(
		vc map[string]interface{},
		headers jose.Headers,
		signer jose.Signer,
		opts ...NewOpt,
	) (*SelectiveDisclosureJWT, error)
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

func (s *SDJWTBuilderV2) NewFromVC(
	vc map[string]interface{},
	headers jose.Headers,
	signer jose.Signer,
	opts ...NewOpt,
) (*SelectiveDisclosureJWT, error) {
	csObj, ok := common.GetKeyFromVC(credentialSubjectKey, vc)
	if !ok {
		return nil, fmt.Errorf("credential subject not found")
	}

	cs, ok := csObj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("credential subject must be an object")
	}

	token, err := New("", cs, nil, &unsecuredJWTSigner{}, opts...)
	if err != nil {
		return nil, err
	}

	selectiveCredentialSubject := utils.CopyMap(token.SignedJWT.Payload)
	// move _sd_alg key from credential subject to vc as per example 4 in spec
	vc[vcKey].(map[string]interface{})[common.SDAlgorithmKey] = selectiveCredentialSubject[common.SDAlgorithmKey]
	delete(selectiveCredentialSubject, common.SDAlgorithmKey)

	// move cnf key from credential subject to vc as per example 4 in spec
	cnfObj, ok := selectiveCredentialSubject[common.CNFKey]
	if ok {
		vc[vcKey].(map[string]interface{})[common.CNFKey] = cnfObj
		delete(selectiveCredentialSubject, common.CNFKey)
	}

	// update VC with 'selective' credential subject
	vc[vcKey].(map[string]interface{})[credentialSubjectKey] = selectiveCredentialSubject

	// sign VC with 'selective' credential subject
	signedJWT, err := afgjwt.NewSigned(vc, headers, signer)
	if err != nil {
		return nil, err
	}

	sdJWT := &SelectiveDisclosureJWT{Disclosures: token.Disclosures, SignedJWT: signedJWT}

	return sdJWT, nil
}

func NewSDJWTBuilderV2() *SDJWTBuilderV2 {
	return &SDJWTBuilderV2{}
}

func (s *SDJWTBuilderV2) CreateDisclosuresAndDigests(
	path string,
	claims map[string]interface{},
	opts *newOpts,
) ([]string, map[string]interface{}, error) { // nolint:lll
	var disclosures []string

	var levelDisclosures []string

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
) (string, error) {
	salt, err := opts.getSalt()
	if err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	disclosure := []interface{}{salt, key, value}

	disclosureBytes, err := opts.jsonMarshal(disclosure)
	if err != nil {
		return "", fmt.Errorf("marshal disclosure: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(disclosureBytes), nil
}
