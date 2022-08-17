/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletjsonld

import (
	_ "embed" //nolint:gci // required for go:embed
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

//go:embed testdata/query_by_example_fmt.json
var sampleQueryByExFmt string //nolint:gochecknoglobals

//go:embed testdata/presentation_definition_fmt.json
var presentationDefinitionFmt string //nolint:gochecknoglobals

func (s *SDKSteps) getQuery(queryType wallet.QueryType, didID string) (json.RawMessage, error) {
	switch queryType {
	case wallet.QueryByExample:
		return []byte(fmt.Sprintf(sampleQueryByExFmt, didID)), nil
	case wallet.PresentationExchange:
		return []byte(fmt.Sprintf(presentationDefinitionFmt, didID)), nil
	}

	return nil, fmt.Errorf("invalid queryType %v", queryType)
}
