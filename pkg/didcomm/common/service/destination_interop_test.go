// +build ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

func TestCreateDestinationFromLegacyDoc(t *testing.T) {
	t.Run("successfully prepared destination", func(t *testing.T) {
		doc := mockdiddoc.GetMockIndyDoc(t)
		dest, err := CreateDestination(doc)
		require.NoError(t, err)
		require.NotNil(t, dest)
		require.Equal(t, dest.ServiceEndpoint, "https://localhost:8090")
		require.Equal(t, doc.Service[0].RoutingKeys, dest.RoutingKeys)
	})
}

func TestB58ToDIDKeys(t *testing.T) {
	t.Run("convert recipient keys in did doc", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockIndyDoc(t)

		recipientKeys := convertAnyB58Keys(didDoc.Service[0].RecipientKeys)
		require.NotNil(t, recipientKeys)
		require.Len(t, recipientKeys, 1)

		pk, err := fingerprint.PubKeyFromDIDKey(recipientKeys[0])
		require.NoError(t, err)
		require.ElementsMatch(t, didDoc.VerificationMethod[0].Value, pk)
	})

	t.Run("no keys given", func(t *testing.T) {
		recipientKeys := convertAnyB58Keys(nil)
		require.Nil(t, recipientKeys)
	})

	t.Run("some keys are converted", func(t *testing.T) {
		inKeys := []string{
			"6SFxbqdqGKtVVmLvXDnq9JP4ziZCG2fJzETpMYHt1VNx",
			"#key1",
			"6oDmCnt5w4h2hEQ12hwvD8w5JdvMDPYMzKNv5yPVomFu",
			"did:key:z6MkjtX1C5tGbsNxcGBdCnkfzPw4pHq3fuufgFNkBpFtviAL",
			"QEaG6QrDbx7dQ7U5Bm1Bqvx3psrGEqSieZACZ1LyU62",
			"/path#fragment",
			"9onu2hZrqtcoiVTkBStZ4N8iLYd24bmuHUvx9w3jb9av",
			"GTcPhsGS3XdkWL5mS8sxsTLzwPfSBCYVY93QeT95U6NQ",
			"?query=value",
			"FFPJcCWHGchhuiE5hV1BTRaiBzXpZfgYdsSPFHu6DSAC",
			"",
			"@!~unexpected data~!@",
		}
		expectedKeys := []string{
			"did:key:z6MkjtX1C5tGbsNxcGBdCnkfzPw4pHq3fuufgFNkBpFtviAL",
			"#key1",
			"did:key:z6MkkFUoo38XGcBVojEhiGum4EV58DCCdGnigLHqvFMWiz3H",
			"did:key:z6MkjtX1C5tGbsNxcGBdCnkfzPw4pHq3fuufgFNkBpFtviAL",
			"did:key:z6MkerVcrLfHZ9SajtxAkkir2wUwsQ9hg85oQfU62pyMtgsQ",
			"/path#fragment",
			"did:key:z6MkoG3wcwpJBS7GpzJSs1rPuTgiA7tsUV2FyVqszD1kWNNJ",
			"did:key:z6MkuusSJ7WsP58DcpvU7hqoiYtzkxwHb5nrE9xLUj76PK9n",
			"?query=value",
			"did:key:z6MktheMCSkicACB2D4nP3y2JX8i1ZofyYvuKtMK5Zs78ewa",
			"",
			"@!~unexpected data~!@",
		}

		outKeys := convertAnyB58Keys(inKeys)

		require.Equal(t, len(expectedKeys), len(outKeys))

		for i := range outKeys {
			require.Equal(t, expectedKeys[i], outKeys[i])

			// if we expect the key to be converted, check if it's converted correctly
			if inKeys[i] != expectedKeys[i] {
				pk, err := fingerprint.PubKeyFromDIDKey(outKeys[i])
				require.NoError(t, err)

				pkb58 := base58.Encode(pk)
				require.Equal(t, inKeys[i], pkb58)
			}
		}
	})
}
