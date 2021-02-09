/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
)

func TestGetRecipientKeys(t *testing.T) {
	t.Run("successfully getting recipient keys", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)

		recipientKeys, ok := LookupDIDCommRecipientKeys(didDoc)
		require.True(t, ok)
		require.Equal(t, 1, len(recipientKeys))
	})

	t.Run("error due to missing did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)
		didDoc.Service = nil

		recipientKeys, ok := LookupDIDCommRecipientKeys(didDoc)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})

	t.Run("error due to missing recipient keys in did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)
		didDoc.Service[0].RecipientKeys = []string{}

		recipientKeys, ok := LookupDIDCommRecipientKeys(didDoc)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})
}

func TestGetDidCommService(t *testing.T) {
	didCommServiceType := "did-communication"

	t.Run("successfully getting did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)

		s, ok := LookupService(didDoc, didCommServiceType)
		require.True(t, ok)
		require.Equal(t, "did-communication", s.Type)
		require.Equal(t, uint(0), s.Priority)
	})

	t.Run("error due to missing service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)
		didDoc.Service = nil

		s, ok := LookupService(didDoc, didCommServiceType)
		require.False(t, ok)
		require.Nil(t, s)
	})

	t.Run("error due to missing did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t)
		didDoc.Service[0].Type = "some-type"

		s, ok := LookupService(didDoc, didCommServiceType)
		require.False(t, ok)
		require.Nil(t, s)
	})
}
