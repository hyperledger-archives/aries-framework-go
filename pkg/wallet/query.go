/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
)

// Query errors.
var (
	// ErrQueryNoResultFound error when no records found from query.
	ErrQueryNoResultFound = errors.New("no result found")
)

// QueryType is type of query supported by wallet implementation
// More details can be found here : https://w3c-ccg.github.io/universal-wallet-interop-spec/#query
type QueryType int

const (
	// QueryByExample https://w3c-ccg.github.io/vp-request-spec/#query-by-example
	QueryByExample QueryType = iota + 1
	// QueryByFrame https://github.com/w3c-ccg/vp-request-spec/issues/8
	QueryByFrame
	// PresentationExchange https://identity.foundation/presentation-exchange/
	PresentationExchange
	// DIDAuth https://w3c-ccg.github.io/vp-request-spec/#did-authentication-request
	DIDAuth
)

// Name returns name of the query.
func (q QueryType) Name() string {
	return []string{"", "QueryByExample", "QueryByFrame", "PresentationExchange"}[q]
}

// GetQueryType returns QueryType instance for given string query type.
func GetQueryType(name string) (QueryType, error) {
	switch strings.ToLower(name) {
	case "querybyexample":
		return QueryByExample, nil
	case "querybyframe":
		return QueryByFrame, nil
	case "presentationexchange":
		return PresentationExchange, nil
	case "didauth":
		return DIDAuth, nil
	default:
		return 0, fmt.Errorf("unsupported query type, supported types - (%s, %s, %s)",
			QueryByExample.Name(), QueryByFrame.Name(), PresentationExchange.Name())
	}
}

// Query performs wallet credential queries, currently supporting all the QueryTypes defined in QueryType.
type Query struct {
	publicKeyFetcher verifiable.PublicKeyFetcher
	documentLoader   ld.DocumentLoader
	params           []*QueryParams
}

// NewQuery returns new wallet query instance.
func NewQuery(pkFetcher verifiable.PublicKeyFetcher, loader ld.DocumentLoader, queries ...*QueryParams) *Query {
	return &Query{publicKeyFetcher: pkFetcher, documentLoader: loader, params: queries}
}

// PerformQuery performs credential query on given credentials.
// nolint:gocyclo
func (q *Query) PerformQuery(credentials map[string]json.RawMessage) ([]*verifiable.Presentation, error) {
	if len(credentials) == 0 {
		return nil, ErrQueryNoResultFound
	}

	vcs, err := q.parseCredentialContents(credentials)
	if err != nil {
		return nil, err
	}

	// using map to remove duplicates from results
	credResults := make(map[*verifiable.Credential]struct{}, len(credentials))

	var results []*verifiable.Presentation

	for _, param := range q.params {
		qType, err := GetQueryType(param.Type)
		if err != nil {
			return nil, err
		}

		credentials, err := q.getCredentials(qType, vcs, param.Query...)
		if err != nil {
			return nil, err
		}

		for _, cred := range credentials {
			credResults[cred] = struct{}{}
		}

		presentations, err := q.getPresentation(qType, vcs, param.Query...)
		if err != nil {
			return nil, err
		}

		results = append(results, presentations...)
	}

	if len(credResults) > 0 {
		presentation, err := preparePresentation(credResults)
		if err != nil {
			return nil, err
		}

		results = append(results, presentation)
	}

	if len(results) == 0 {
		return nil, ErrQueryNoResultFound
	}

	return results, nil
}

// getCredentials runs given query and returns query result as credentials.
func (q *Query) getCredentials(qType QueryType, vcs []*verifiable.Credential, query ...json.RawMessage) ([]*verifiable.Credential, error) { // nolint: lll
	switch qType {
	case QueryByExample:
		return queryByExample(vcs, query...)
	case QueryByFrame:
		return queryByFrame(vcs, q.publicKeyFetcher, q.documentLoader, query...)
	default:
		return []*verifiable.Credential{}, nil
	}
}

// getPresentation runs given query and returns query result as presentation.
func (q *Query) getPresentation(qType QueryType, vcs []*verifiable.Credential, query ...json.RawMessage) ([]*verifiable.Presentation, error) { // nolint: lll
	switch qType {
	case PresentationExchange:
		return q.queryByPresentationExchange(vcs, query...)
	case DIDAuth:
		return didAuth()
	default:
		return []*verifiable.Presentation{}, nil
	}
}

type credentialMatcher struct {
	example *ExampleDefinition
	frame   *QueryByFrameDefinition
}

func (cm *credentialMatcher) MatchExample(credential *verifiable.Credential) bool { // nolint: funlen,gocognit,gocyclo
	// Match context
	if !contains(credential.Context, cm.example.Context) {
		return false
	}

	// Match type
	if !contains(credential.Types, cm.example.Type) {
		return false
	}

	// Issuer match
	issuerMatched := len(cm.example.TrustedIssuer) == 0

	for _, ti := range cm.example.TrustedIssuer {
		matched := strings.EqualFold(credential.Issuer.ID, ti.Issuer)

		// if not matched & this trusted issuer required then return false
		if !matched && ti.Required {
			return false
		}

		issuerMatched = issuerMatched || matched
	}

	// if none matched then return false
	if !issuerMatched {
		return false
	}

	// Match Credential Schema ID
	if schemaID, ok := cm.example.CredentialSchema["id"]; ok {
		schemaIDMatched := false

		for _, schema := range credential.Schemas {
			if schemaID == schema.ID {
				schemaIDMatched = true
			}
		}

		if !schemaIDMatched {
			return false
		}
	}

	// Match Credential Schema Type
	if schemaType, ok := cm.example.CredentialSchema["type"]; ok {
		schemaTypeMatched := false

		for _, schema := range credential.Schemas {
			if strings.EqualFold(schemaType, schema.Type) {
				schemaTypeMatched = true
			}
		}

		if !schemaTypeMatched {
			return false
		}
	}

	// Match credential subject
	if cm.example.CredentialSubject != nil {
		credSubjID, err := verifiable.SubjectID(credential.Subject)
		if err != nil {
			return false
		}

		if querySubjectID, ok := cm.example.CredentialSubject["id"]; ok && credSubjID != querySubjectID {
			return false
		}
	}

	return true
}

func (cm *credentialMatcher) MatchFrame(credential *verifiable.Credential) bool {
	// Issuer match
	issuerMatched := len(cm.frame.TrustedIssuer) == 0

	for _, ti := range cm.frame.TrustedIssuer {
		matched := strings.EqualFold(credential.Issuer.ID, ti.Issuer)

		// if not matched & this trusted issuer required then return false
		if !matched && ti.Required {
			return false
		}

		issuerMatched = issuerMatched || matched
	}

	// also check if VC has bbs signature
	for _, proof := range credential.Proofs {
		if proof["type"] == BbsBlsSignature2020 {
			return true
		}
	}

	return false
}

func preparePresentation(credentials map[*verifiable.Credential]struct{}) (*verifiable.Presentation, error) {
	var opts []verifiable.CreatePresentationOpt

	for cred := range credentials {
		opts = append(opts, verifiable.WithCredentials(cred))
	}

	return verifiable.NewPresentation(opts...)
}

// proof check is disabled while resolving credentials from raw bytes. A wallet implementation may or may not choose to
// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
// may to call 'wallet.Verify()' for each credential being presented.
// (More details can be found in issue #2677).
func (q *Query) parseCredentialContents(raws map[string]json.RawMessage) ([]*verifiable.Credential, error) {
	var result []*verifiable.Credential

	for _, raw := range raws {
		vc, err := verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(q.documentLoader))
		if err != nil {
			return nil, err
		}

		result = append(result, vc)
	}

	return result, nil
}

func parseQueryByExample(defs ...json.RawMessage) ([]*QueryByExampleDefinition, error) {
	definitions := make([]*QueryByExampleDefinition, len(defs))

	for i, def := range defs {
		var query QueryByExampleDefinition

		err := json.Unmarshal(def, &query)
		if err != nil {
			return nil, err
		}

		if query.Example == nil {
			return nil, errors.New("invalid QueryByExample, 'example' is required")
		}

		if query.Example.Context == nil {
			return nil, errors.New("invalid QueryByExample, 'example.context' is required")
		}

		if isEmpty(query.Example.Type) {
			return nil, errors.New("invalid QueryByExample, 'example.type' is required")
		}

		definitions[i] = &query
	}

	return definitions, nil
}

func parseQueryByFrame(defs ...json.RawMessage) ([]*QueryByFrameDefinition, error) {
	definitions := make([]*QueryByFrameDefinition, len(defs))

	for i, def := range defs {
		var query QueryByFrameDefinition

		err := json.Unmarshal(def, &query)
		if err != nil {
			return nil, err
		}

		if len(query.Frame) == 0 {
			return nil, errors.New("invalid QueryByFrame, 'frame' is required")
		}

		definitions[i] = &query
	}

	return definitions, nil
}

func queryByExample(vcs []*verifiable.Credential, defs ...json.RawMessage) ([]*verifiable.Credential, error) {
	definitions, err := parseQueryByExample(defs...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse QueryByExample query: %w", err)
	}

	var result []*verifiable.Credential

	for _, vc := range vcs {
		for _, definition := range definitions {
			matcher := &credentialMatcher{example: definition.Example}

			if matcher.MatchExample(vc) {
				result = append(result, vc)
			}
		}
	}

	return result, nil
}

func queryByFrame(vcs []*verifiable.Credential, publicKeyFetcher verifiable.PublicKeyFetcher, loader ld.DocumentLoader,
	defs ...json.RawMessage) ([]*verifiable.Credential, error) {
	definitions, err := parseQueryByFrame(defs...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse QueryByFrame query: %w", err)
	}

	var result []*verifiable.Credential

	for _, vc := range vcs {
		for _, definition := range definitions {
			matcher := &credentialMatcher{frame: definition}

			// match trusted issuer
			if !matcher.MatchFrame(vc) {
				continue
			}

			// match frame
			bbsVC, err := vc.GenerateBBSSelectiveDisclosure(definition.Frame, nil,
				verifiable.WithPublicKeyFetcher(publicKeyFetcher),
				verifiable.WithJSONLDDocumentLoader(loader))
			if err != nil {
				continue
			}

			result = append(result, bbsVC)
		}
	}

	return result, nil
}

// queryByPresentationExchange generates presentation submission result based on given query.
func (q *Query) queryByPresentationExchange(vcs []*verifiable.Credential, defs ...json.RawMessage) ([]*verifiable.Presentation, error) { // nolint:lll
	var results []*verifiable.Presentation

	for _, def := range defs {
		var presDefinition presexch.PresentationDefinition

		err := json.Unmarshal(def, &presDefinition)
		if err != nil {
			return nil, err
		}

		result, err := presDefinition.CreateVP(vcs, q.documentLoader, verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(q.documentLoader))

		if errors.Is(err, presexch.ErrNoCredentials) {
			continue
		}

		if err != nil {
			return nil, err
		}

		results = append(results, result)
	}

	return results, nil
}

// didAuth prepares presentation for DID authorization.
func didAuth() ([]*verifiable.Presentation, error) {
	presentation, err := verifiable.NewPresentation()
	if err != nil {
		return nil, err
	}

	return []*verifiable.Presentation{presentation}, nil
}

func contains(slice []string, item interface{}) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	switch itemVal := item.(type) {
	case string:
		_, ok := set[itemVal]

		return ok
	case []interface{}:
		for _, val := range itemVal {
			_, ok := set[val.(string)]
			if !ok {
				return false
			}
		}

		return true
	case []string:
		for _, val := range itemVal {
			_, ok := set[val]
			if !ok {
				return false
			}
		}

		return true
	default:
		return false
	}
}

func isEmpty(item interface{}) bool {
	switch itemVal := item.(type) {
	case string:
		return itemVal == ""
	case []interface{}:
		return len(itemVal) == 0
	case []string:
		return len(itemVal) == 0
	default:
		return itemVal == nil
	}
}
