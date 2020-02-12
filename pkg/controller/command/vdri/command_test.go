/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
)

func TestOperation_CreatePublicDID(t *testing.T) {
	t.Run("Test successful create public DID with method", func(t *testing.T) {
		cmd := New(&protocol.MockProvider{})
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.NotEmpty(t, handlers)

		var b bytes.Buffer
		req := []byte(`{"method":"sidetree"}`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))
		require.NoError(t, cmdErr)

		var response CreatePublicDIDResponse
		err := json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
		require.NotEmpty(t, response.DID.ID)
		require.NotEmpty(t, response.DID.PublicKey)
		require.NotEmpty(t, response.DID.Service)
	})

	t.Run("Test successful create public DID with request header", func(t *testing.T) {
		cmd := New(&protocol.MockProvider{})
		require.NotNil(t, cmd)

		var b bytes.Buffer
		req := []byte(`{"method":"sidetree", "header":"{}"}`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))
		require.NoError(t, cmdErr)

		var response CreatePublicDIDResponse
		err := json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
		require.NotEmpty(t, response.DID.ID)
		require.NotEmpty(t, response.DID.PublicKey)
		require.NotEmpty(t, response.DID.Service)
	})

	t.Run("Test create public DID validation error", func(t *testing.T) {
		cmd := New(&protocol.MockProvider{})
		require.NotNil(t, cmd)

		var b bytes.Buffer
		req := []byte(`"""`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))

		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Type(), command.ValidationError)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Contains(t, cmdErr.Error(), "cannot unmarshal")

		req = []byte(`{}`)
		cmdErr = cmd.CreatePublicDID(&b, bytes.NewBuffer(req))

		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Type(), command.ValidationError)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Contains(t, cmdErr.Error(), errDIDMethodMandatory)
	})

	t.Run("Failed Create public DID, VDRI error", func(t *testing.T) {
		const errMsg = "just fail it error"
		cmd := New(&protocol.MockProvider{CustomVDRI: &mockvdri.MockVDRIRegistry{CreateErr: fmt.Errorf(errMsg)}})
		require.NotNil(t, cmd)

		var b bytes.Buffer
		req := []byte(`{"method":"sidetree"}`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
		require.Equal(t, cmdErr.Code(), CreatePublicDIDError)
		require.Contains(t, cmdErr.Error(), errMsg)
	})
}

func TestBuildSideTreeRequest(t *testing.T) {
	registry := mockvdri.MockVDRIRegistry{}
	didDoc, err := registry.Create("sidetree")
	require.NoError(t, err)
	require.NotNil(t, didDoc)

	b, err := didDoc.JSONBytes()
	require.NoError(t, err)

	r, err := getBasicRequestBuilder(`{"operation":"create"}`)(b)
	require.NoError(t, err)
	require.NotNil(t, r)

	r, err = getBasicRequestBuilder(`--`)(b)
	require.Error(t, err)
	require.Nil(t, r)
}
