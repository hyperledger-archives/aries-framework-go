/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/common/connectionstore"

	"github.com/stretchr/testify/require"

	mockroute "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/route"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          mockstore.NewMockStoreProvider(),
			ServiceValue:                  &mockroute.MockRouteSvc{}})
		require.NoError(t, err)
	})

	t.Run("test error from get service from context", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceErr: fmt.Errorf("service error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})

	t.Run("test error from cast service", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceValue: nil})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to route service failed")
	})

	t.Run("test error from open store", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store")},
			ServiceValue:         &mockroute.MockRouteSvc{},
			InboundEndpointValue: "endpoint"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})

	t.Run("test error from open transient store", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			TransientStorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open transient store")},
			ServiceValue:         &mockroute.MockRouteSvc{},
			InboundEndpointValue: "endpoint"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open transient store")
	})
}

func TestSendRequest(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s := make(map[string][]byte)
		c, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ServiceValue: &mockroute.MockRouteSvc{SendRequestFunc: func(myDID, theirDID string) (s string, err error) {
				require.Equal(t, myDID, "mydid")
				require.Equal(t, theirDID, "theirDID")
				return "1", nil
			}}})
		require.NoError(t, err)

		connRec := &connectionstore.ConnectionRecord{
			ConnectionID: "conn1", MyDID: "mydid", TheirDID: "theirDID", State: "complete"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		s["conn_conn1"] = connBytes

		id, err := c.SendRequest("conn1")
		require.NoError(t, err)
		require.Equal(t, id, "1")
	})

	t.Run("test failure from send request", func(t *testing.T) {
		s := make(map[string][]byte)
		c, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ServiceValue: &mockroute.MockRouteSvc{SendRequestFunc: func(myDID, theirDID string) (s string, err error) {
				return "", fmt.Errorf("send request error")
			}}})
		require.NoError(t, err)

		connRec := &connectionstore.ConnectionRecord{
			ConnectionID: "conn1", MyDID: "mydid", TheirDID: "theirDID", State: "complete"}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		s["conn_conn1"] = connBytes

		_, err = c.SendRequest("conn1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "send request error")
	})

	t.Run("test error connection not found", func(t *testing.T) {
		s := make(map[string][]byte)
		c, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue:          &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ServiceValue:                  &mockroute.MockRouteSvc{}})
		require.NoError(t, err)

		_, err = c.SendRequest("conn1")
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrConnectionNotFound.Error())
	})

	t.Run("test error from get connection record", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			TransientStorageProviderValue: mockstore.NewMockStoreProvider(),
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{ErrGet: fmt.Errorf("get error")}},
			ServiceValue: &mockroute.MockRouteSvc{}})
		require.NoError(t, err)

		_, err = c.SendRequest("conn1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error")
	})
}
