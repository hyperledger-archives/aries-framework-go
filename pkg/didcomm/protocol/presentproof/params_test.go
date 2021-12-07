/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package presentproof

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const foo = "foo"

func TestProposePresentationParams_UnmarshalJSON(t *testing.T) {
	tests := testTable(
		&ProposePresentationParams{},
		&ProposePresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		return &ProposePresentationParams{}
	}, tests)
}

func TestRequestPresentationParams_UnmarshalJSON(t *testing.T) {
	tests := testTable(
		&RequestPresentationParams{},
		&RequestPresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		// this function returns an object for the test to unmarshal into
		return &RequestPresentationParams{}
	}, tests)
}

func TestPresentationParams_UnmarshalJSON(t *testing.T) {
	tests := testTable(
		&PresentationParams{},
		&PresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		// this function returns an object for the test to unmarshal into
		return &PresentationParams{}
	}, tests)
}

func testTable(expectedEmpty, expectedWithComment interface{}) []testCase {
	return []testCase{
		{
			name:     "empty",
			srcBytes: []byte(`{}`),
			expect:   expectedEmpty,
		},
		{
			name:     "id v2",
			srcBytes: []byte(`{"@id":"foo"}`),
			expect:   expectedEmpty,
		},
		{
			name:     "type v2",
			srcBytes: []byte(`{"@type":"foo"}`),
			expect:   expectedEmpty,
		},
		{
			name:     "comment v2",
			srcBytes: []byte(`{"comment":"foo"}`),
			expect:   expectedWithComment,
		},
		{
			name:     "id v3",
			srcBytes: []byte(`{"id":"foo"}`),
			expect:   expectedEmpty,
		},
		{
			name:     "type v3",
			srcBytes: []byte(`{"type":"foo"}`),
			expect:   expectedEmpty,
		},
		{
			name:     "comment v3",
			srcBytes: []byte(`{"body":{"comment":"foo"}}`),
			expect:   expectedWithComment,
		},
	}
}

type testCase struct {
	name     string
	src      interface{}
	srcBytes []byte
	expect   interface{}
}

type freshObjGetter func() interface{}

func handleTestSet(t *testing.T, getEmptyObject freshObjGetter, tests []testCase) {
	t.Parallel()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := getEmptyObject()
			err := marshalUnmarshalTest(t, tc.src, tc.srcBytes, result, tc.expect)
			if err != nil {
				t.FailNow()
			}
		})
	}
}

func marshalUnmarshalTest(t *testing.T, src interface{}, srcBytes []byte, unMarshalTo, expected interface{}) error {
	t.Helper()

	var (
		dataBytes []byte
		err       error
	)

	if srcBytes != nil {
		dataBytes = srcBytes
	} else {
		dataBytes, err = json.Marshal(src)
		require.NoError(t, err)
	}

	require.NoError(t, json.Unmarshal(dataBytes, unMarshalTo))

	if !assert.Equal(t, expected, unMarshalTo) {
		return fmt.Errorf("")
	}

	return nil
}
