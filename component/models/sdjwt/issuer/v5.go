package issuer

import (
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"

	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	utils "github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
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
func (s *SDJWTBuilderV5) NewFromVC(vc map[string]interface{}, headers jose.Headers, signer jose.Signer, opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	claims := utils.CopyMap(vc)
	for _, key := range s.keysToExclude() {
		delete(claims, key)
	}
	token, err := New("", claims, nil, &unsecuredJWTSigner{}, opts...)
	if err != nil {
		return nil, err
	}

	selectiveCredentialSubject := utils.CopyMap(token.SignedJWT.Payload)
	// move _sd_alg key from credential subject to vc as per example 4 in spec
	vc[common.SDAlgorithmKey] = selectiveCredentialSubject[common.SDAlgorithmKey]
	delete(selectiveCredentialSubject, common.SDAlgorithmKey)

	// move cnf key from credential subject to vc as per example 4 in spec
	cnfObj, ok := selectiveCredentialSubject[common.CNFKey]
	if ok {
		vc[common.CNFKey] = cnfObj
		delete(selectiveCredentialSubject, common.CNFKey)
	}

	// update VC with 'selective' credential subject
	for k := range claims {
		delete(vc, k)
	}
	for k, v := range selectiveCredentialSubject {
		vc[k] = v
	}

	// sign VC with 'selective' credential subject
	signedJWT, err := afgjwt.NewSigned(vc, headers, signer)
	if err != nil {
		return nil, err
	}

	sdJWT := &SelectiveDisclosureJWT{Disclosures: token.Disclosures, SignedJWT: signedJWT}

	return sdJWT, nil
}

func NewSDJWTBuilderV5() *SDJWTBuilderV5 {
	return &SDJWTBuilderV5{}
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

	var allDisclosures []string
	for key, value := range claims {
		curPath := key
		if path != "" {
			curPath = path + "." + key
		}

		kind := reflect.TypeOf(value).Kind()
		if kind == reflect.Map && opts.structuredClaims {
			// todo
			//nestedDisclosures, nestedDigestsMap, e := s.CreateDisclosuresAndDigests(curPath,
			//	value.(map[string]interface{}), opts)
			//if e != nil {
			//	return nil, nil, e
			//}

			//digestsMap[key] = nestedDigestsMap

			//disclosures = append(disclosures, nestedDisclosures...)
		} else if kind == reflect.Array || kind == reflect.Slice {
			valSl := reflect.ValueOf(value)
			var digestArr []map[string]string
			for i := 0; i < valSl.Len(); i++ {
				digest, e := s.createDisclosure("", valSl.Index(i).Interface(),
					opts)
				if e != nil {
					return nil, nil, fmt.Errorf("create disclosure: %w", e)
				}

				digestArr = append(digestArr, map[string]string{"...": digest})
				allDisclosures = append(allDisclosures, digest)
			}
			if opts.structuredClaims {
				digestsMap[key] = digestArr
			} else {
				disclosure, e := s.createDisclosure(key, digestArr, opts)
				if e != nil {
					return nil, nil, fmt.Errorf("create disclosure: %w", e)
				}

				finalSDDigest = append(finalSDDigest, disclosure)
				allDisclosures = append(allDisclosures, disclosure)
			}
		} else {
			if _, ok := opts.nonSDClaimsMap[curPath]; ok {
				//digestsMap[key] = value

				continue
			}

			disclosure, e := s.createDisclosure(key, value, opts)
			if e != nil {
				return nil, nil, fmt.Errorf("create disclosure: %w", e)
			}

			finalSDDigest = append(finalSDDigest, disclosure)
			allDisclosures = append(allDisclosures, disclosure)
			//rootLevelDisclosures = append(rootLevelDisclosures, disclosure)
		}
	}

	//disclosures = append(disclosures, rootLevelDisclosures...)

	digests, err := createDigests(finalSDDigest, opts)
	if err != nil {
		return nil, nil, err
	}

	digestsMap[common.SDKey] = digests

	return allDisclosures, digestsMap, nil
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
