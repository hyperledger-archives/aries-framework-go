/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
)

const errorMessageTestNameFormat = "Test name: %s"

// Marshals the presentation and then unmarshals it again so that the type of the custom fields matches the type of
// the expected presentation - this allows us to use reflect.DeepEqual to compare them.
func marshalThenUnmarshalAgain(t *testing.T, presentation *verifiable.Presentation,
	testName string) *verifiable.Presentation {
	presentationBytes, err := json.Marshal(presentation)
	require.NoError(t, err, errorMessageTestNameFormat, testName)

	return makePresentationFromBytes(t, presentationBytes, testName)
}

func makePresentationFromBytes(t *testing.T, presentationBytes []byte, testName string) *verifiable.Presentation {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	presentation, err := verifiable.ParsePresentation(presentationBytes,
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	require.NoError(t, err, errorMessageTestNameFormat, testName)

	return presentation
}
