/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endpoint

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewEndpoint(t *testing.T) {
	uri := "uri"
	accept := []string{"accept"}
	routingkeys := []string{"key1"}

	didCommV2Endpoint := Endpoint{
		rawDIDCommV2: []DIDCommV2Endpoint{{
			URI:         uri,
			Accept:      accept,
			RoutingKeys: routingkeys,
		}},
	}

	ep := NewDIDCommV2Endpoint([]DIDCommV2Endpoint{{uri, accept, routingkeys}})
	require.EqualValues(t, didCommV2Endpoint, ep)
	require.Equal(t, DIDCommV2, ep.Type())

	didCommV1Endpoint := Endpoint{
		rawDIDCommV1: uri,
	}

	ep = NewDIDCommV1Endpoint(uri)
	require.EqualValues(t, didCommV1Endpoint, ep)
	require.Equal(t, DIDCommV1, ep.Type())

	didCoreEndpoint := Endpoint{
		rawObj: []string{uri, "uri2"},
	}

	ep = NewDIDCoreEndpoint([]string{uri, "uri2"})
	require.EqualValues(t, didCoreEndpoint, ep)
	require.Equal(t, Generic, ep.Type())

	ep = NewDIDCommV1Endpoint("")
	require.EqualValues(t, Endpoint{}, ep)

	m, err := ep.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, m, []byte("null"))

	err = ep.UnmarshalJSON([]byte(""))
	require.EqualError(t, err, "endpoint data is not supported")
}

func TestEndpoint_MarshalUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name          string
		endpoint      interface{}
		expectedValue interface{}
		err           error
	}{
		{
			name: "marshal Endpoint for DIDComm V2",
			endpoint: Endpoint{
				rawDIDCommV2: []DIDCommV2Endpoint{{
					URI:    "https://agent.example.com/",
					Accept: []string{"didcomm/v2"},
				}},
			},
			expectedValue: []byte(`[{"uri":"https://agent.example.com/","accept":["didcomm/v2"]}]`),
		},
		{
			name: "marshal Endpoint for DIDcomm V1",
			endpoint: Endpoint{
				rawDIDCommV1: "https://agent.example.com/",
			},
			expectedValue: []byte(fmt.Sprintf("%q", "https://agent.example.com/")),
			err:           nil,
		},
		{
			name: "marshal random DIDCore Endpoint (neither DIDcomm V1 nor V2) as interface{}",
			endpoint: Endpoint{
				rawObj: []interface{}{"some random endpoint", "some other endpoint"},
			},
			expectedValue: []byte(`["some random endpoint","some other endpoint"]`),
			err:           nil,
		},
		{
			name: "marshal random DIDCore Endpoint (neither DIDcomm V1 nor V2) as map[string]interface{}",
			endpoint: Endpoint{
				rawObj: map[string]interface{}{"origins": []interface{}{"some random endpoint"}},
			},
			expectedValue: []byte(`{"origins":["some random endpoint"]}`),
			err:           nil,
		},
	}

	for _, tc := range testCases {
		ep, ok := tc.endpoint.(Endpoint)
		if !ok {
			continue
		}

		mep, err := ep.MarshalJSON()
		require.NoError(t, err)
		require.EqualValues(t, tc.expectedValue, mep)

		newEP := Endpoint{}
		err = newEP.UnmarshalJSON(mep)
		require.NoError(t, err)
		require.EqualValues(t, ep, newEP)

		uri, err := newEP.URI()
		require.NoError(t, err)

		switch tc.name {
		case "marshal Endpoint for DIDComm V2":
			require.Equal(t, ep.rawDIDCommV2[0].URI, uri)

			accept, e := newEP.Accept()
			require.NoError(t, e)
			require.Equal(t, ep.rawDIDCommV2[0].Accept, accept)

			routingKeys, e := newEP.RoutingKeys()
			require.NoError(t, e)
			require.Equal(t, ep.rawDIDCommV2[0].RoutingKeys, routingKeys)
		case "marshal Endpoint for DIDcomm V1":
			require.Equal(t, ep.rawDIDCommV1, uri)

			_, err = newEP.Accept()
			require.EqualError(t, err, "endpoint Accept not found")

			_, err = newEP.RoutingKeys()
			require.EqualError(t, err, "endpoint RoutingKeys not found")
		case "marshal random DIDCore Endpoint (neither DIDcomm V1 nor V2) as interface{}":
			require.Equal(t, ep.rawObj.([]interface{})[0], uri)
		}
	}
}
