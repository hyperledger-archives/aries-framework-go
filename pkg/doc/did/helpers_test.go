/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/internal/mock/diddoc"
)

func TestGetRecipientKeys(t *testing.T) {
	ed25519KeyType := "Ed25519VerificationKey2018"
	didCommServiceType := "did-communication"

	t.Run("successfully getting recipient keys", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()

		recipientKeys, ok := LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
		require.True(t, ok)
		require.Equal(t, 1, len(recipientKeys))
	})

	t.Run("error due to missing did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service = nil

		recipientKeys, ok := LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})

	t.Run("error due to missing recipient keys in did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service[0].RecipientKeys = []string{}

		recipientKeys, ok := LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})

	t.Run("error due to missing public key in did doc", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service[0].RecipientKeys = []string{"invalid"}

		recipientKeys, ok := LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})

	t.Run("error due to unsupported key types", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service[0].RecipientKeys = []string{didDoc.PublicKey[0].ID}

		recipientKeys, ok := LookupRecipientKeys(didDoc, didCommServiceType, ed25519KeyType)
		require.False(t, ok)
		require.Nil(t, recipientKeys)
	})
}

func TestGetDidCommService(t *testing.T) {
	didCommServiceType := "did-communication"

	t.Run("successfully getting did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()

		s, ok := LookupService(didDoc, didCommServiceType)
		require.True(t, ok)
		require.Equal(t, "did-communication", s.Type)
		require.Equal(t, uint(0), s.Priority)
	})

	t.Run("error due to missing service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service = nil

		s, ok := LookupService(didDoc, didCommServiceType)
		require.False(t, ok)
		require.Nil(t, s)
	})

	t.Run("error due to missing did-communication service", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc()
		didDoc.Service[0].Type = "some-type"
		didDoc.Service[1].Type = "other-type"

		s, ok := LookupService(didDoc, didCommServiceType)
		require.False(t, ok)
		require.Nil(t, s)
	})
}
