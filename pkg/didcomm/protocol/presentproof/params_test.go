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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

const foo = "foo"

func TestProposePresentationParams_UnmarshalJSON(t *testing.T) {
	tests := testTable(
		&ProposePresentationParams{},
		&ProposePresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		return &ProposePresentationParams{}
	}, tests, jsonUnmarshalTest)

	t.Run("fail: parse error", func(t *testing.T) {
		unMarshalTo := &ProposePresentationParams{}
		dataBytes := []byte("{{{{bad json")

		require.Error(t, json.Unmarshal(dataBytes, unMarshalTo))
	})
}

func TestProposePresentationParams_FromDIDCommMsgMap(t *testing.T) {
	tests := testTable(
		&ProposePresentationParams{},
		&ProposePresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		return &ProposePresentationParams{}
	}, tests, msgMapDecodeTest)
}

func TestRequestPresentationParams_UnmarshalJSON(t *testing.T) {
	tests := testTable(
		&RequestPresentationParams{},
		&RequestPresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		// this function returns an object for the test to unmarshal into
		return &RequestPresentationParams{}
	}, tests, jsonUnmarshalTest)

	t.Run("fail: parse error", func(t *testing.T) {
		unMarshalTo := &RequestPresentationParams{}
		dataBytes := []byte("{{{{bad json")

		require.Error(t, json.Unmarshal(dataBytes, unMarshalTo))
	})
}

func TestRequestPresentationParams_FromDIDCommMsgMap(t *testing.T) {
	tests := testTable(
		&RequestPresentationParams{},
		&RequestPresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		// this function returns an object for the test to unmarshal into
		return &RequestPresentationParams{}
	}, tests, msgMapDecodeTest)
}

func TestPresentationParams_UnmarshalJSON(t *testing.T) {
	tests := testTable(
		&PresentationParams{},
		&PresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		// this function returns an object for the test to unmarshal into
		return &PresentationParams{}
	}, tests, jsonUnmarshalTest)

	t.Run("fail: parse error", func(t *testing.T) {
		unMarshalTo := &PresentationParams{}
		dataBytes := []byte("{{{{bad json")

		require.Error(t, json.Unmarshal(dataBytes, unMarshalTo))
	})
}

func TestPresentationParams_FromDIDCommMsgMap(t *testing.T) {
	tests := testTable(
		&PresentationParams{},
		&PresentationParams{Comment: foo},
	)

	handleTestSet(t, func() interface{} {
		// this function returns an object for the test to unmarshal into
		return &PresentationParams{}
	}, tests, msgMapDecodeTest)
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
	srcBytes []byte
	expect   interface{}
}

type freshObjGetter func() interface{}

type unmarshalTester func(t *testing.T, srcBytes []byte, unMarshalTo, expected interface{}) error

func handleTestSet(t *testing.T, getEmptyObject freshObjGetter, tests []testCase, testFunc unmarshalTester) {
	t.Parallel()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := getEmptyObject()
			err := testFunc(t, tc.srcBytes, result, tc.expect)
			if err != nil {
				t.FailNow()
			}
		})
	}
}

func jsonUnmarshalTest(t *testing.T, srcBytes []byte, unMarshalTo, expected interface{}) error {
	t.Helper()

	require.NoError(t, json.Unmarshal(srcBytes, unMarshalTo))

	if !assert.Equal(t, expected, unMarshalTo) {
		return fmt.Errorf("")
	}

	return nil
}

func msgMapDecodeTest(t *testing.T, srcBytes []byte, unMarshalTo, expected interface{}) error {
	t.Helper()

	msg, err := service.ParseDIDCommMsgMap(srcBytes)
	require.NoError(t, err)

	require.NoError(t, msg.Decode(unMarshalTo))

	if !assert.Equal(t, expected, unMarshalTo) {
		return fmt.Errorf("")
	}

	return nil
}
