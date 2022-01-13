/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	MYDID    = "sample-my-did"
	THEIRDID = "sample-their-did"
)

func TestServiceNew(t *testing.T) {
	t.Run("test new service - success", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)
		require.Equal(t, MessagePickup, svc.Name())
	})

	t.Run("test new service name - store error", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error opening the store"),
			},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "open mailbox store")
		require.Nil(t, svc)
	})
}

func TestService_Initialize(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		prov := &mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		}

		svc := Service{}

		err := svc.Initialize(prov)
		require.NoError(t, err)

		// second init is no-op
		err = svc.Initialize(prov)
		require.NoError(t, err)
	})

	t.Run("failure, not given a valid provider", func(t *testing.T) {
		svc := Service{}

		err := svc.Initialize("not a provider")
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected provider of type")
	})
}

func TestHandleInbound(t *testing.T) {
	t.Run("test MessagePickupService.HandleInbound() - Status", func(t *testing.T) {
		const jsonStr = `{
			"@id": "123456781",
			"@type": "https://didcomm.org/messagepickup/1.0/status",
			"message_count": 7,
			"duration_waited": 3600,
			"last_added_time": "2019-05-01T12:00:00Z",
			"last_delivered_time": "2019-05-01T12:00:00Z",
			"last_removed_time": "2019-05-01T12:00:00Z",
			"total_size": 8096
		}`

		svc, err := getService()
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
		require.NoError(t, err)

		statusCh := make(chan Status)
		svc.setStatusCh(msg.ID(), statusCh)

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(MYDID, THEIRDID, nil))
		require.NoError(t, err)

		tyme, err := time.Parse(time.RFC3339, "2019-05-01T12:00:00Z")
		require.NoError(t, err)

		select {
		case x := <-svc.statusMap[msg.ID()]:
			require.NotNil(t, x)
			require.Equal(t, "123456781", x.ID)
			require.Equal(t, 3600, x.DurationWaited)
			require.Equal(t, tyme, x.LastAddedTime)
			require.Equal(t, tyme, x.LastDeliveredTime)
			require.Equal(t, tyme, x.LastRemovedTime)
			require.Equal(t, 7, x.MessageCount)
			require.Equal(t, 8096, x.TotalSize)

		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive message to handle")
		}
	})

	t.Run("test MessagePickupService.HandleInbound() - unknown type", func(t *testing.T) {
		const jsonStr = `{
			"@id": "123456781",
			"@type": "unknown"
		}`

		svc, err := getService()
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
		require.NoError(t, err)

		statusCh := make(chan Status)
		svc.setStatusCh(msg.ID(), statusCh)

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(MYDID, THEIRDID, nil))
		require.NoError(t, err)
	})

	t.Run("test MessagePickupService.HandleInbound() - Status - msg error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}
		err = svc.handleStatus(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "status message unmarshal")
	})

	t.Run("test MessagePickupService.HandleInbound() - StatusRequest success", func(t *testing.T) {
		const jsonStr = `{
			"@id": "123456781",
			"@type": "https://didcomm.org/messagepickup/1.0/status-request",
			"~thread" : {"thid": "2d798168-8abf-4410-8535-bc1e8406a5ff"}
		}`
		msgID := make(chan string)

		tyme, err := time.Parse(time.RFC3339, "2019-05-01T12:00:00Z")
		require.NoError(t, err)

		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					request := &Status{}

					err = reqMsgMap.Decode(request)
					require.NoError(t, err)

					require.Equal(t, 1, request.MessageCount)
					require.Equal(t, tyme, request.LastAddedTime)
					require.Equal(t, tyme, request.LastDeliveredTime)
					require.Equal(t, tyme, request.LastRemovedTime)
					require.Equal(t, 3096, request.TotalSize)
					require.Equal(t, "2d798168-8abf-4410-8535-bc1e8406a5ff", request.Thread.PID)

					msgID <- request.ID

					return nil
				},
			},
			PackagerValue: &mockPackager{},
		})
		require.NoError(t, err)

		b, err := json.Marshal(inbox{
			DID:               "sample-their-did",
			MessageCount:      1,
			LastAddedTime:     tyme,
			LastDeliveredTime: tyme,
			LastRemovedTime:   tyme,
			TotalSize:         3096,
			Messages:          []byte(`[{"test": "message"}]`),
		})
		require.NoError(t, err)

		err = svc.msgStore.Put(THEIRDID, b)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
		require.NoError(t, err)

		go func() {
			_, err = svc.HandleInbound(msg, service.NewDIDCommContext(MYDID, THEIRDID, nil))
			require.NoError(t, err)
		}()

		select {
		case id := <-msgID:
			require.NotNil(t, id)
			require.Equal(t, "123456781", id)

		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive message to handle")
		}
	})

	t.Run("test MessagePickupService.HandleInbound() - StatusRequest - msg error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}
		err = svc.handleStatusRequest(msg, MYDID, THEIRDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "status request message unmarshal")
	})

	t.Run("test MessagePickupService.HandleInbound() - StatusRequest - get error", func(t *testing.T) {
		const jsonStr = `{
			"@id": "123456781",
			"@type": "https://didcomm.org/messagepickup/1.0/status-request",
			"~thread" : {"thid": "2d798168-8abf-4410-8535-bc1e8406a5ff"}
		}`

		svc, err := getService()
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
		require.NoError(t, err)

		err = svc.handleStatusRequest(msg, MYDID, "not found")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error in status request getting inbox")
	})

	t.Run("test MessagePickupService.HandleInbound() - BatchPickup", func(t *testing.T) {
		msgID := make(chan string)

		tyme, err := time.Parse(time.RFC3339, "2019-05-01T12:00:00Z")
		require.NoError(t, err)

		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					request := &Batch{}

					err = reqMsgMap.Decode(request)
					require.NoError(t, err)

					require.Equal(t, 2, len(request.Messages))

					msgID <- request.ID

					return nil
				},
			},
			PackagerValue: &mockPackager{},
		})
		require.NoError(t, err)

		b, err := json.Marshal(inbox{
			DID:               "sample-their-did",
			MessageCount:      2,
			LastAddedTime:     tyme,
			LastDeliveredTime: tyme,
			LastRemovedTime:   tyme,
			TotalSize:         3096,
			Messages:          []byte(`[{"id": "8910"}, {"id": "8911"}, {"id": "8912"}]`),
		})
		require.NoError(t, err)

		err = svc.msgStore.Put(THEIRDID, b)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(`{
			"@id": "123456781",
			"@type": "https://didcomm.org/messagepickup/1.0/batch-pickup",
			"batch_size": 2,
			"~thread" : {"thid": "2d798168-8abf-4410-8535-bc1e8406a5ff"}
		}`))
		require.NoError(t, err)

		go func() {
			_, err = svc.HandleInbound(msg, service.NewDIDCommContext(MYDID, THEIRDID, nil))
			require.NoError(t, err)
		}()

		select {
		case id := <-msgID:
			require.NotNil(t, id)
			require.Equal(t, id, "123456781")

		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive message to handle")
		}
	})

	t.Run("test MessagePickupService.HandleInbound() - BatchPickup - msg error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}
		err = svc.handleBatchPickup(msg, MYDID, THEIRDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch pickup message unmarshal")
	})

	t.Run("test MessagePickupService.HandleInbound() - BatchPickup - get error", func(t *testing.T) {
		mockStore := mockstore.NewMockStoreProvider()
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockStore,
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})
		require.NoError(t, err)

		mockStore.Store.ErrGet = errors.New("error get inbox")

		msg, err := service.ParseDIDCommMsgMap([]byte(`{
			"@id": "123456781",
			"@type": "https://didcomm.org/messagepickup/1.0/batch-pickup",
			"batch_size": 2,
			"~thread" : {"thid": "2d798168-8abf-4410-8535-bc1e8406a5ff"}
		}`))
		require.NoError(t, err)

		err = svc.handleBatchPickup(msg, MYDID, THEIRDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get inbox")
	})

	t.Run("test MessagePickupService.pullMessages() - put inbox error", func(t *testing.T) {
		mockStore := mockstore.NewMockStoreProvider()
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockStore,
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})
		require.NoError(t, err)

		b, err := json.Marshal(&inbox{DID: THEIRDID})
		require.NoError(t, err)

		err = mockStore.Store.Put(THEIRDID, b)
		require.NoError(t, err)

		mockStore.Store.ErrPut = errors.New("error put inbox")

		msg, err := service.ParseDIDCommMsgMap([]byte(`{
			"@id": "123456781",
			"@type": "https://didcomm.org/messagepickup/1.0/batch-pickup",
			"batch_size": 2,
			"~thread" : {"thid": "2d798168-8abf-4410-8535-bc1e8406a5ff"}
		}`))
		require.NoError(t, err)

		err = svc.handleBatchPickup(msg, MYDID, THEIRDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put inbox")
	})

	t.Run("test MessagePickupService.HandleInbound() - Batch", func(t *testing.T) {
		const jsonStr = `{ 
			"@id": "123456781", 
			"@type": "https://didcomm.org/messagepickup/1.0/batch", 
			"messages~attach": [ 
				{ 
					"@id" : "06ca25f6-d3c5-48ac-8eee-1a9e29120c31", 
					"message" : "{\"id\": \"8910\"}"
				}, 
				{ 	
					"@id" : "344a51cf-379f-40ab-ab2c-711dab3f53a9a", 
					"message" : "{\"id\": \"8910\"}"
				} 
			] 
		}`

		svc, err := getService()
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
		require.NoError(t, err)

		batchCh := make(chan Batch)
		svc.setBatchCh(msg.ID(), batchCh)

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(MYDID, THEIRDID, nil))
		require.NoError(t, err)

		select {
		case x := <-svc.batchMap[msg.ID()]:
			require.NotNil(t, x)
			require.Equal(t, "123456781", x.ID)
			require.Equal(t, 2, len(x.Messages))

		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive message to handle")
		}
	})

	t.Run("test MessagePickupService.HandleInbound() - Batch - msg error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}
		err = svc.handleBatch(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch message unmarshal")
	})

	t.Run("test MessagePickupService.HandleInbound() - Noop", func(t *testing.T) {
		const jsonStr = `{ 
			"@id": "123456781", 
			"@type": "https://didcomm.org/messagepickup/1.0/noop"
		}`

		svc, err := getService()
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
		require.NoError(t, err)

		_, err = svc.HandleInbound(msg, service.NewDIDCommContext(MYDID, THEIRDID, nil))
		require.NoError(t, err)
	})

	t.Run("test MessagePickupService.HandleInbound() - Noop - msg error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}
		err = svc.handleNoop(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "noop message unmarshal")
	})
}

func TestAccept(t *testing.T) {
	t.Run("test MessagePickupService.Accept() - Status", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		require.True(t, svc.Accept(StatusMsgType))
		require.True(t, svc.Accept(StatusRequestMsgType))
		require.True(t, svc.Accept(NoopMsgType))
		require.True(t, svc.Accept(BatchMsgType))
		require.True(t, svc.Accept(BatchPickupMsgType))
		require.False(t, svc.Accept("random-msg-type"))
	})
}

func TestAddMessage(t *testing.T) {
	t.Run("test MessagePickupService.AddMessage() to new inbox - success", func(t *testing.T) {
		mockStore := mockstore.NewMockStoreProvider()
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockStore,
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})
		require.NoError(t, err)

		message := []byte(`{
			Protected: "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1t" +
				"ZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
			IV:         "JS2FxjEKdndnt-J7QX5pEnVwyBTu0_3d",
			CipherText: "qQyzvajdvCDJbwxM",
			Tag:        "2FqZMMQuNPYfL0JsSkj8LQ",
		}`)

		err = svc.AddMessage(message, THEIRDID)
		require.NoError(t, err)

		b, err := mockStore.Store.Get(THEIRDID)
		require.NoError(t, err)

		ibx := &inbox{}
		err = json.Unmarshal(b, ibx)
		require.NoError(t, err)

		require.Equal(t, 1, ibx.MessageCount)
	})

	t.Run("test MessagePickupService.AddMessage() to existing inbox - success", func(t *testing.T) {
		mockStore := mockstore.NewMockStoreProvider()
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockStore,
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})
		require.NoError(t, err)

		message := []byte(`{
			Protected: "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1t" +
				"ZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
			IV:         "JS2FxjEKdndnt-J7QX5pEnVwyBTu0_3d",
			CipherText: "qQyzvajdvCDJbwxM",
			Tag:        "2FqZMMQuNPYfL0JsSkj8LQ",
		}`)

		tyme, err := time.Parse(time.RFC3339, "2019-05-01T12:00:00Z")
		require.NoError(t, err)

		b, err := json.Marshal(inbox{
			DID:               "sample-their-did",
			MessageCount:      3,
			LastAddedTime:     tyme,
			LastDeliveredTime: tyme,
			LastRemovedTime:   tyme,
			TotalSize:         3096,
			Messages:          []byte(`[{"id": "8910"}, {"id": "8911"}, {"id": "8912"}]`),
		})
		require.NoError(t, err)

		err = svc.msgStore.Put(THEIRDID, b)
		require.NoError(t, err)

		err = svc.AddMessage(message, THEIRDID)
		require.NoError(t, err)

		b, err = mockStore.Store.Get(THEIRDID)
		require.NoError(t, err)

		ibx := &inbox{}
		err = json.Unmarshal(b, ibx)
		require.NoError(t, err)

		require.Equal(t, 4, ibx.MessageCount)
	})

	t.Run("test MessagePickupService.AddMessage() - put error", func(t *testing.T) {
		mockStore := mockstore.NewMockStoreProvider()
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockStore,
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})
		require.NoError(t, err)

		b, err := json.Marshal(inbox{
			DID: "sample-their-did",
		})
		require.NoError(t, err)

		// seed data for initial get in AddMessage
		err = mockStore.Store.Put(THEIRDID, b)
		require.NoError(t, err)

		mockStore.Store.ErrPut = errors.New("error put")

		message := []byte("")

		err = svc.AddMessage(message, THEIRDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("test MessagePickupService.AddMessage() - get error", func(t *testing.T) {
		mockStore := mockstore.NewMockStoreProvider()
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue:              mockStore,
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})
		require.NoError(t, err)

		message := []byte("")

		mockStore.Store.ErrGet = errors.New("error get")

		err = svc.AddMessage(message, "not found")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
	})
}

func TestStatusRequest(t *testing.T) {
	t.Run("test MessagePickupService.StatusRequest() - success", func(t *testing.T) {
		msgID := make(chan string)
		s := make(map[string][]byte)

		provider := &mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					request, ok := msg.(*StatusRequest)
					require.True(t, ok)

					msgID <- request.ID

					return nil
				},
			},
			PackagerValue: &mockPackager{},
		}

		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "completed",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)

		s["conn_conn1"] = connBytes

		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		svc, err := New(provider)
		require.NoError(t, err)

		go func() {
			status, err := svc.StatusRequest("conn")
			require.NoError(t, err)

			require.Equal(t, 6, status.MessageCount)
		}()

		select {
		case id := <-msgID:
			require.NotNil(t, id)
			s := Status{
				MessageCount: 6,
			}

			// outbound has been handled, simulate a callback to finish the trip
			ch := svc.getStatusCh(id)
			ch <- s

		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive message to handle")
		}
	})

	t.Run("test MessagePickupService.StatusRequest() - connection error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		expected := errors.New("get error")
		svc.connectionLookup = &connectionsStub{
			getConnRecord: func(string) (*connection.Record, error) {
				return nil, expected
			},
		}

		_, err = svc.StatusRequest("conn")
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("test MessagePickupService.StatusRequest() - send to DID error", func(t *testing.T) {
		s := make(map[string][]byte)

		provider := &mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					return errors.New("send error")
				},
			},
			PackagerValue: &mockPackager{},
		}

		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "completed",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)

		s["conn_conn1"] = connBytes

		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		svc, err := New(provider)
		require.NoError(t, err)

		_, err = svc.StatusRequest("conn")
		require.Error(t, err)
		require.Contains(t, err.Error(), "send route request")
	})
}

func TestBatchPickup(t *testing.T) {
	t.Run("test MessagePickupService.BatchPickup() - success", func(t *testing.T) {
		msgID := make(chan string)
		s := make(map[string][]byte)

		provider := &mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					batchpickup := &BatchPickup{}

					err := reqMsgMap.Decode(batchpickup)
					require.NoError(t, err)

					require.True(t, ok)

					require.Equal(t, 1, batchpickup.BatchSize)
					msgID <- batchpickup.ID

					return nil
				},
			},
			PackagerValue:              &mockPackager{},
			InboundMessageHandlerValue: (&mockTransportProvider{}).InboundMessageHandler(),
		}

		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "completed",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)

		s["conn_conn1"] = connBytes

		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		svc, err := New(provider)
		require.NoError(t, err)

		go func() {
			id := <-msgID
			require.NotNil(t, id)

			s := Batch{
				Messages: []*Message{{Message: []byte(`{
					Protected: "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1t" +
						"ZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
					IV:         "JS2FxjEKdndnt-J7QX5pEnVwyBTu0_3d",
					CipherText: "qQyzvajdvCDJbwxM",
					Tag:        "2FqZMMQuNPYfL0JsSkj8LQ",
				}`)}},
			}

			// outbound has been handled, simulate a callback to finish the trip
			ch := svc.getBatchCh(id)
			ch <- s
		}()

		p, err := svc.BatchPickup("conn", 1)
		require.NoError(t, err)

		require.Equal(t, 1, p)
	})

	t.Run("test MessagePickupService.BatchPickup() - connection error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		expected := errors.New("get error")
		svc.connectionLookup = &connectionsStub{
			getConnRecord: func(string) (*connection.Record, error) {
				return nil, expected
			},
		}

		p, err := svc.BatchPickup("conn", 4)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
		require.Equal(t, -1, p)
	})

	t.Run("test MessagePickupService.BatchPickup() - send to DID error", func(t *testing.T) {
		s := make(map[string][]byte)

		provider := &mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					return errors.New("send error")
				},
			},
			PackagerValue: &mockPackager{},
		}

		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "completed",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)

		s["conn_conn1"] = connBytes

		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		svc, err := New(provider)
		require.NoError(t, err)

		_, err = svc.BatchPickup("conn", 4)
		require.Error(t, err)
		require.Contains(t, err.Error(), "send batch pickup request")
	})
}

func TestDecodeMessages(t *testing.T) {
	t.Run("test inbox.DecodeMessages() - success", func(t *testing.T) {
		ibx := &inbox{}

		msgs, err := ibx.DecodeMessages()
		require.NoError(t, err)
		require.Empty(t, msgs)
	})

	t.Run("test inbox.DecodeMessages() - error", func(t *testing.T) {
		b, err := json.Marshal([]*Message{})
		require.NoError(t, err)

		ibx := &inbox{
			Messages: b,
		}

		_, err = ibx.DecodeMessages()
		require.NoError(t, err)
	})
}

func TestHandleOutbound(t *testing.T) {
	t.Run("test MessagePickupService.HandleOutbound() - not implemented", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		svc.connectionLookup = &connectionsStub{
			getConnRecord: func(string) (*connection.Record, error) {
				return nil, storage.ErrDataNotFound
			},
		}

		_, err = svc.HandleOutbound(nil, "not", "implemented")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
	})
}

func TestNoop(t *testing.T) {
	t.Run("test MessagePickupService.Noop() - success", func(t *testing.T) {
		s := make(map[string][]byte)

		provider := &mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					request := &Noop{}

					err := reqMsgMap.Decode(request)
					require.NoError(t, err)

					return nil
				},
			},
			PackagerValue: &mockPackager{},
		}

		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "completed",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)

		s["conn_conn1"] = connBytes

		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.Noop("conn")
		require.NoError(t, err)
	})

	t.Run("test MessagePickupService.Noop() - send to DID error", func(t *testing.T) {
		s := make(map[string][]byte)

		provider := &mockprovider.Provider{
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					return errors.New("send error")
				},
			},
			PackagerValue: &mockPackager{},
		}

		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "completed",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)

		s["conn_conn1"] = connBytes

		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		svc, err := New(provider)
		require.NoError(t, err)

		err = svc.Noop("conn")
		require.Error(t, err)
		require.Contains(t, err.Error(), "send noop request")
	})

	t.Run("test MessagePickupService.Noop() - connection error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		expected := errors.New("get error")
		svc.connectionLookup = &connectionsStub{
			getConnRecord: func(string) (*connection.Record, error) {
				return nil, expected
			},
		}

		err = svc.Noop("conn")
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestGetConnection(t *testing.T) {
	t.Run("test MessagePickupService.getConnection() - error", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)

		svc.connectionLookup = &connectionsStub{
			getConnRecord: func(string) (*connection.Record, error) {
				return nil, storage.ErrDataNotFound
			},
		}

		_, err = svc.getConnection("test")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrConnectionNotFound))
	})
}

func getService() (*Service, error) {
	svc, err := New(&mockprovider.Provider{
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		OutboundDispatcherValue:           nil,
		PackagerValue:                     &mockPackager{},
	})

	return svc, err
}

// mockProvider mock provider.
type mockTransportProvider struct {
	packagerValue transport.Packager
}

func (p *mockTransportProvider) Packager() transport.Packager {
	return p.packagerValue
}

func (p *mockTransportProvider) InboundMessageHandler() transport.InboundMessageHandler {
	return func(envelope *transport.Envelope) error {
		logger.Debugf("message received is %s", envelope.Message)
		return nil
	}
}

func (p *mockTransportProvider) AriesFrameworkID() string {
	return "aries-framework-instance-1"
}

// mockPackager mock packager.
type mockPackager struct{}

func (m *mockPackager) PackMessage(e *transport.Envelope) ([]byte, error) {
	return e.Message, nil
}

func (m *mockPackager) UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	return &transport.Envelope{
		Message: []byte(`{
			"id": "8910",     
			"~transport": {
				"return_route": "all"
			}
		}`),
	}, nil
}

type connectionsStub struct {
	getConnIDByDIDs func(string, string) (string, error)
	getConnRecord   func(string) (*connection.Record, error)
}

func (c *connectionsStub) GetConnectionIDByDIDs(myDID, theirDID string) (string, error) {
	if c.getConnIDByDIDs != nil {
		return c.getConnIDByDIDs(myDID, theirDID)
	}

	return "", nil
}

func (c *connectionsStub) GetConnectionRecord(id string) (*connection.Record, error) {
	if c.getConnRecord != nil {
		return c.getConnRecord(id)
	}

	return nil, nil
}
