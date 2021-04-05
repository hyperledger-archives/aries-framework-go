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
)

// GeneratePresentation runs given query and generates presentation from query result.
func (q QueryType) GeneratePresentation(credentials []json.RawMessage, query json.RawMessage) (*verifiable.Presentation, error) { // nolint: lll
	vcs, err := parseCredentials(credentials)
	if err != nil {
		return nil, err
	}

	if len(vcs) == 0 {
		return nil, ErrQueryNoResultFound
	}

	switch q {
	case QueryByExample:
		return nil, fmt.Errorf("to be implemented")
	case QueryByFrame:
		return nil, fmt.Errorf("to be implemented")
	case PresentationExchange:
		return queryByPresentationExchange(vcs, query)
	default:
		return nil, fmt.Errorf("unsupported query type, supported types - (%s, %s, %s)",
			QueryByExample.Name(), QueryByFrame.Name(), PresentationExchange.Name())
	}
}

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
	default:
		return 0, fmt.Errorf("unsupported query type, supported types - (%s, %s, %s)",
			QueryByExample.Name(), QueryByFrame.Name(), PresentationExchange.Name())
	}
}

// proof check is disabled while resolving credentials from raw bytes. A wallet implementation may or may not choose to
// show credentials as verified. If a wallet implementation chooses to show credentials as 'verified' it
// may to call 'wallet.Verify()' for each credential being presented.
// (More details can be found in issue #2677).
func parseCredentials(raws []json.RawMessage) ([]*verifiable.Credential, error) {
	var result []*verifiable.Credential

	for _, raw := range raws {
		vc, err := verifiable.ParseCredential(raw, verifiable.WithDisabledProofCheck())
		if err != nil {
			return nil, err
		}

		result = append(result, vc)
	}

	return result, nil
}

// queryByPresentationExchange generates presentation submission result based on given query.
func queryByPresentationExchange(vcs []*verifiable.Credential, def json.RawMessage) (*verifiable.Presentation, error) {
	var presDefinition presexch.PresentationDefinition

	err := json.Unmarshal(def, &presDefinition)
	if err != nil {
		return nil, err
	}

	return presDefinition.CreateVP(vcs, verifiable.WithDisabledProofCheck())
}
