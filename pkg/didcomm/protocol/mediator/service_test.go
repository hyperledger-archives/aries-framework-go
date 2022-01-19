/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	mockmessagep "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/messagepickup"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
)

const (
	MYDID    = "myDID"
	THEIRDID = "theirDID"
	ENDPOINT = "http://router.example.com"
)

type updateResult struct {
	action string
	result string
}

func TestServiceNew(t *testing.T) {
	t.Run("test new service - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mem.NewProvider(),
			ProtocolStateStorageProviderValue: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.Equal(t, Coordination, svc.Name())
	})

	t.Run("test new service name - failure", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error opening the store"),
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "open route coordination store")
		require.Nil(t, svc)
	})
}

func TestService_Initialize(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		prov := &mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mem.NewProvider(),
			ProtocolStateStorageProviderValue: mem.NewProvider(),
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

func TestServiceAccept(t *testing.T) {
	s := &Service{}

	require.Equal(t, true, s.Accept(RequestMsgType))
	require.Equal(t, true, s.Accept(GrantMsgType))
	require.Equal(t, true, s.Accept(KeylistUpdateMsgType))
	require.Equal(t, true, s.Accept(KeylistUpdateResponseMsgType))
	require.Equal(t, true, s.Accept(service.ForwardMsgType))
	require.Equal(t, false, s.Accept("unsupported msg type"))
}

func TestServiceHandleInbound(t *testing.T) {
	t.Run("test handle inbound ", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mem.NewProvider(),
			ProtocolStateStorageProviderValue: mem.NewProvider(),
		})
		require.NoError(t, err)

		msgID := randomID()

		id, err := svc.HandleInbound(&service.DIDCommMsgMap{"@id": msgID}, service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.Equal(t, msgID, id)
	})
}

func TestServiceHandleOutbound(t *testing.T) {
	t.Run("outbound route-request", func(t *testing.T) {
		msgID := make(chan string)

		provider := &mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mem.NewProvider(),
			ProtocolStateStorageProviderValue: mem.NewProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					request := &Request{}

					err := reqMsgMap.Decode(request)
					require.NoError(t, err)

					msgID <- request.ID
					return nil
				},
			},
		}
		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "completed",
		}

		r, err := connection.NewRecorder(provider)
		require.NoError(t, err)
		err = r.SaveConnectionRecord(connRec)
		require.NoError(t, err)

		svc, err := New(provider)
		require.NoError(t, err)

		go func() {
			id := <-msgID
			require.NoError(t, svc.saveGrant(generateGrantMsgPayload(t, id)))
		}()

		thing, err := svc.HandleOutbound(service.NewDIDCommMsgMap(&Request{
			ID:   uuid.New().String(),
			Type: RequestMsgType,
		}), MYDID, THEIRDID)
		require.NoError(t, err)
		println(thing)
	})

	t.Run("rejects invalid msg types", func(t *testing.T) {
		_, err := (&Service{}).HandleOutbound(service.NewDIDCommMsgMap(&Request{
			Type: "invalid",
		}), "myDID", "theirDID")
		require.Error(t, err)
	})

	t.Run("rejects unsupported route protocol messages", func(t *testing.T) {
		_, err := (&Service{}).HandleOutbound(service.NewDIDCommMsgMap(&Request{
			Type: GrantMsgType,
		}), "myDID", "theirDID")
		require.Error(t, err)
	})

	t.Run("wraps error getting connection ID", func(t *testing.T) {
		expected := errors.New("test")
		s, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		s.connectionLookup = &connectionsStub{
			getConnIDByDIDs: func(string, string) (string, error) {
				return "", expected
			},
		}
		_, err = s.HandleOutbound(service.NewDIDCommMsgMap(
			&Request{Type: RequestMsgType}),
			"myDID", "theirDID",
		)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("wraps error getting connection record", func(t *testing.T) {
		expected := errors.New("test")
		s, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		s.connectionLookup = &connectionsStub{
			getConnRecord: func(string) (*connection.Record, error) {
				return nil, expected
			},
		}
		_, err = s.HandleOutbound(service.NewDIDCommMsgMap(
			&Request{Type: RequestMsgType}),
			"myDID", "theirDID",
		)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestServiceRequestMsg(t *testing.T) {
	t.Run("test service handle inbound request msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		err = svc.RegisterActionEvent(make(chan service.DIDCommAction))
		require.NoError(t, err)

		msgID := randomID()

		id, err := svc.HandleInbound(generateRequestMsgPayload(t, msgID), service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.Equal(t, msgID, id)
	})

	t.Run("test service handle request msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}

		err = svc.handleInboundRequest(&callback{
			msg:      msg,
			myDID:    MYDID,
			theirDID: THEIRDID,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "route request message unmarshal")
	})

	t.Run("test service handle request msg - verify outbound message", func(t *testing.T) {
		endpoint := "ws://agent.example.com"
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			ServiceEndpointValue:              endpoint,
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSend: func(msg interface{}, senderVerKey string, des *service.Destination) error {
					res, err := json.Marshal(msg)
					require.NoError(t, err)

					grant := &Grant{}
					err = json.Unmarshal(res, grant)
					require.NoError(t, err)

					require.Equal(t, endpoint, grant.Endpoint)
					require.Equal(t, 1, len(grant.RoutingKeys))

					return nil
				},
			},
		})
		require.NoError(t, err)

		msgID := randomID()

		err = svc.handleInboundRequest(&callback{
			msg:      generateRequestMsgPayload(t, msgID),
			myDID:    MYDID,
			theirDID: THEIRDID,
			options:  &Options{},
		})
		require.NoError(t, err)
	})

	t.Run("test service handle request msg - kms failure", func(t *testing.T) {
		expected := errors.New("test")
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue: &mockkms.KeyManager{
				CrAndExportPubKeyErr: expected,
			},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		err = svc.handleInboundRequest(&callback{
			msg:      service.NewDIDCommMsgMap(&Request{ID: "test", Type: RequestMsgType}),
			myDID:    MYDID,
			theirDID: THEIRDID,
			options:  &Options{},
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

//nolint:gocyclo
func TestEvents(t *testing.T) {
	t.Run("HandleInbound dispatches action events", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		events := make(chan service.DIDCommAction)

		err = svc.RegisterActionEvent(events)
		require.NoError(t, err)

		msgID := randomID()
		msg := generateRequestMsgPayload(t, msgID)

		id, err := svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.Equal(t, msgID, id)

		select {
		case e := <-events:
			require.Equal(t, msg, e.Message)
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}
	})

	t.Run("continuing inbound request event dispatches outbound grant", func(t *testing.T) {
		dispatched := make(chan struct{})
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					dispatched <- struct{}{}
					return nil
				},
			},
		})
		require.NoError(t, err)

		events := make(chan service.DIDCommAction)

		err = svc.RegisterActionEvent(events)
		require.NoError(t, err)

		_, err = svc.HandleInbound(generateRequestMsgPayload(t, "123"), service.EmptyDIDCommContext())
		require.NoError(t, err)

		select {
		case e := <-events:
			e.Continue(service.Empty{})
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}

		select {
		case <-dispatched:
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}
	})

	t.Run("stopping inbound request event does not dispatch outbound grant", func(t *testing.T) {
		dispatched := make(chan struct{})
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					dispatched <- struct{}{}
					return nil
				},
			},
		})
		require.NoError(t, err)

		events := make(chan service.DIDCommAction)

		err = svc.RegisterActionEvent(events)
		require.NoError(t, err)

		_, err = svc.HandleInbound(generateRequestMsgPayload(t, "123"), service.EmptyDIDCommContext())
		require.NoError(t, err)

		select {
		case e := <-events:
			e.Stop(errors.New("rejected"))
		case <-time.After(time.Second):
			require.Fail(t, "timeout")
		}

		select {
		case <-dispatched:
			require.Fail(t, "stopping the protocol flow should not result in an outbound message dispatch")
		case <-time.After(time.Second):
		}
	})

	t.Run("fails when no listeners are registered for action events", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		_, err = svc.HandleInbound(generateRequestMsgPayload(t, "123"), service.EmptyDIDCommContext())
		require.Error(t, err)
	})

	t.Run("Continue assigns keys and endpoint provided by user", func(t *testing.T) {
		endpoint := "ws://agent.example.com"
		routingKeys := []string{"key1", "key2"}
		dispatched := make(chan struct{})
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			ServiceEndpointValue:              "http://other.com",
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					res, err := json.Marshal(msg)
					require.NoError(t, err)

					grant := &Grant{}
					err = json.Unmarshal(res, grant)
					require.NoError(t, err)

					require.Equal(t, endpoint, grant.Endpoint)
					require.Equal(t, routingKeys, grant.RoutingKeys)

					dispatched <- struct{}{}

					return nil
				},
			},
		})
		require.NoError(t, err)

		events := make(chan service.DIDCommAction)
		err = svc.RegisterActionEvent(events)
		require.NoError(t, err)

		t.Run("with Options as a struct type", func(t *testing.T) {
			_, err = svc.HandleInbound(generateRequestMsgPayload(t, randomID()), service.NewDIDCommContext(MYDID, THEIRDID, nil))
			require.NoError(t, err)

			select {
			case event := <-events:
				event.Continue(Options{
					ServiceEndpoint: endpoint,
					RoutingKeys:     routingKeys,
				})
			case <-time.After(time.Second):
				require.Fail(t, "timeout")
			}

			select {
			case <-dispatched:
			case <-time.After(time.Second):
				require.Fail(t, "timeout")
			}
		})

		t.Run("with Options as a pointer type", func(t *testing.T) {
			_, err = svc.HandleInbound(generateRequestMsgPayload(t, randomID()), service.NewDIDCommContext(MYDID, THEIRDID, nil))
			require.NoError(t, err)

			select {
			case event := <-events:
				event.Continue(&Options{
					ServiceEndpoint: endpoint,
					RoutingKeys:     routingKeys,
				})
			case <-time.After(time.Second):
				require.Fail(t, "timeout")
			}

			select {
			case <-dispatched:
			case <-time.After(time.Second):
				require.Fail(t, "timeout")
			}
		})
	})
}

func TestServiceGrantMsg(t *testing.T) {
	t.Run("test service handle inbound grant msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msgID := randomID()

		id, err := svc.HandleInbound(generateGrantMsgPayload(t, msgID), service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.Equal(t, msgID, id)
	})

	t.Run("service handle grant msg - marshal error", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": make(chan int64)}

		err = svc.saveGrant(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshal grant: json")
	})
}

func TestServiceUpdateKeyListMsg(t *testing.T) {
	t.Run("test service handle inbound key list update msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msgID := randomID()

		id, err := svc.HandleInbound(generateKeyUpdateListMsgPayload(t, msgID, []Update{{
			RecipientKey: "ABC",
			Action:       "add",
		}}), service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.Equal(t, msgID, id)
	})

	t.Run("test service handle key list update msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}

		err = svc.handleKeylistUpdate(msg, MYDID, THEIRDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "route key list update message unmarshal")
	})

	t.Run("test service handle request msg - verify outbound message", func(t *testing.T) {
		update := make(map[string]updateResult)
		update["ABC"] = updateResult{action: add, result: success}
		update["XYZ"] = updateResult{action: remove, result: serverError}
		update[""] = updateResult{action: add, result: success}

		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSend: func(msg interface{}, senderVerKey string, des *service.Destination) error {
					res, err := json.Marshal(msg)
					require.NoError(t, err)

					updateRes := &KeylistUpdateResponse{}
					err = json.Unmarshal(res, updateRes)
					require.NoError(t, err)

					require.Equal(t, len(update), len(updateRes.Updated))

					for _, v := range updateRes.Updated {
						require.Equal(t, update[v.RecipientKey].action, v.Action)
						require.Equal(t, update[v.RecipientKey].result, v.Result)
					}

					return nil
				},
			},
		})
		require.NoError(t, err)

		msgID := randomID()

		var updates []Update
		for k, v := range update {
			updates = append(updates, Update{
				RecipientKey: k,
				Action:       v.action,
			})
		}

		err = svc.handleKeylistUpdate(generateKeyUpdateListMsgPayload(t, msgID, updates), MYDID, THEIRDID)
		require.NoError(t, err)
	})
}

func TestServiceKeylistUpdateResponseMsg(t *testing.T) {
	t.Run("test service handle inbound key list update response msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msgID := randomID()

		id, err := svc.HandleInbound(generateKeylistUpdateResponseMsgPayload(t, msgID, []UpdateResponse{{
			RecipientKey: "ABC",
			Action:       "add",
			Result:       success,
		}}), service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.Equal(t, msgID, id)
	})

	t.Run("test service handle key list update response msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}

		err = svc.handleKeylistUpdateResponse(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "route keylist update response message unmarshal")
	})
}

func TestServiceForwardMsg(t *testing.T) {
	t.Run("test service handle inbound forward msg - success", func(t *testing.T) {
		to := randomID()
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		err = svc.routeStore.Put(to, []byte("did:example:123"))
		require.NoError(t, err)

		msgID := randomID()

		id, err := svc.HandleInbound(generateForwardMsgPayload(t, msgID, to, nil), service.EmptyDIDCommContext())
		require.NoError(t, err)
		require.Equal(t, msgID, id)
	})

	t.Run("test service handle forward msg - success", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		msg := &service.DIDCommMsgMap{"@id": map[int]int{}}

		err = svc.handleForward(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "forward message unmarshal")
	})

	t.Run("test service handle forward msg - route key fetch fail", func(t *testing.T) {
		to := randomID()
		msgID := randomID()

		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		err = svc.handleForward(generateForwardMsgPayload(t, msgID, to, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "route key fetch")
	})

	t.Run("test service handle forward msg - validate forward message content", func(t *testing.T) {
		to := randomID()
		msgID := randomID()
		invalidDID := "did:error:123"

		content := []byte(`{
			Protected: "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1t" +
				"ZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
			IV:         "JS2FxjEKdndnt-J7QX5pEnVwyBTu0_3d",
			CipherText: "qQyzvajdvCDJbwxM",
			Tag:        "2FqZMMQuNPYfL0JsSkj8LQ",
		}`)

		msg := generateForwardMsgPayload(t, msgID, to, content)

		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateForward: func(msg interface{}, des *service.Destination) error {
					require.Equal(t, content, msg)

					return nil
				},
			},
			VDRegistryValue: &mockvdr.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (doc *did.DocResolution, e error) {
					if didID == invalidDID {
						return nil, errors.New("invalid")
					}
					return &did.DocResolution{DIDDocument: mockdiddoc.GetMockDIDDoc(t)}, nil
				},
			},
		})
		require.NoError(t, err)

		err = svc.routeStore.Put(dataKey(to), []byte("did:example:123"))
		require.NoError(t, err)

		err = svc.handleForward(msg)
		require.NoError(t, err)

		err = svc.routeStore.Put(dataKey(to), []byte(invalidDID))
		require.NoError(t, err)

		err = svc.handleForward(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get destination")
	})
}

func TestMessagePickup(t *testing.T) {
	t.Run("test service handle inbound message pick up - success", func(t *testing.T) {
		to := randomID()

		content := []byte(`{
			Protected: "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1t" +
				"ZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
			IV:         "JS2FxjEKdndnt-J7QX5pEnVwyBTu0_3d",
			CipherText: "qQyzvajdvCDJbwxM",
			Tag:        "2FqZMMQuNPYfL0JsSkj8LQ",
		}`)

		svc, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{
						AddMessageFunc: func(message []byte, theirDID string) error {
							require.Equal(t, content, message)
							return nil
						},
					},
				},
				StorageProviderValue:              mockstore.NewMockStoreProvider(),
				ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
				KMSValue:                          &mockkms.KeyManager{},
				OutboundDispatcherValue: &mockdispatcher.MockOutbound{
					ValidateForward: func(_ interface{}, _ *service.Destination) error {
						return errors.New("websocket connection failed")
					},
				},
				VDRegistryValue: &mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
						return &did.DocResolution{DIDDocument: mockdiddoc.GetMockDIDDoc(t)}, nil
					},
				},
			})
		require.NoError(t, err)

		err = svc.routeStore.Put(dataKey(to), []byte("did:example:123"))
		require.NoError(t, err)

		msgID := randomID()
		msg := generateForwardMsgPayload(t, msgID, to, content)

		err = svc.handleForward(msg)
		require.NoError(t, err)
	})

	t.Run("test service handle inbound message pick up - add message error", func(t *testing.T) {
		to := randomID()

		content := []byte(`{
			Protected: "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1t" +
				"ZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
			IV:         "JS2FxjEKdndnt-J7QX5pEnVwyBTu0_3d",
			CipherText: "qQyzvajdvCDJbwxM",
			Tag:        "2FqZMMQuNPYfL0JsSkj8LQ",
		}`)

		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{
					AddMessageErr: errors.New("add error"),
				},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateForward: func(_ interface{}, _ *service.Destination) error {
					return errors.New("websocket connection failed")
				},
			},
			VDRegistryValue: &mockvdr.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (doc *did.DocResolution, e error) {
					return &did.DocResolution{DIDDocument: mockdiddoc.GetMockDIDDoc(t)}, nil
				},
			},
		})
		require.NoError(t, err)

		err = svc.routeStore.Put(dataKey(to), []byte("did:example:123"))
		require.NoError(t, err)

		msgID := randomID()
		msg := generateForwardMsgPayload(t, msgID, to, content)

		err = svc.handleForward(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "add error")
	})
}

func TestRegister(t *testing.T) {
	t.Run("test register route - success", func(t *testing.T) {
		msgID := make(chan string)

		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					request := &Request{}

					err := reqMsgMap.Decode(request)
					require.NoError(t, err)

					msgID <- request.ID
					return nil
				},
			},
		})
		require.NoError(t, err)

		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "complete",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		s["conn_conn"] = mockstore.DBEntry{Value: connBytes}

		go func() {
			id := <-msgID
			require.NoError(t, svc.saveGrant(generateGrantMsgPayload(t, id)))
		}()

		err = svc.Register("conn")
		require.NoError(t, err)

		err = svc.Register("conn")
		require.Error(t, err)
		require.Contains(t, err.Error(), "router is already registered")
	})

	t.Run("test register route - with client timeout error", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		connRec := &connection.Record{
			ConnectionID: "conn2", MyDID: MYDID, TheirDID: THEIRDID, State: "complete",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		s["conn_conn2"] = mockstore.DBEntry{Value: connBytes}

		err = svc.Register("conn2", func(opts *ClientOptions) {
			opts.Timeout = 1 * time.Millisecond
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "get grant for request ID '")
		require.Contains(t, err.Error(), "': store: data not found")
	})

	t.Run("test register route - router connection not found", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              mockstore.NewMockStoreProvider(),
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					return fmt.Errorf("error send")
				},
			},
		})
		require.NoError(t, err)

		err = svc.Register("conn")
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrConnectionNotFound.Error())
	})

	t.Run("test register route - router connection fetch error", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{ErrGet: fmt.Errorf("get error")},
			},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					return fmt.Errorf("error send")
				},
			},
		})
		require.NoError(t, err)

		err = svc.Register("conn")
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch connection record from store")
	})
}

func TestUnregister(t *testing.T) {
	const connID = "conn-id"

	t.Run("test unregister route - success", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
				},
				StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
				ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			},
		)
		require.NoError(t, err)

		s[fmt.Sprintf(routeConnIDDataKey, connID)] = mockstore.DBEntry{Value: []byte("conn-abc-xyz")}

		err = svc.Unregister(connID)
		require.NoError(t, err)
	})

	t.Run("test unregister route - router not registered", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
				},
				StorageProviderValue: &mockstore.MockStoreProvider{
					Store: &mockstore.MockStore{Store: s},
				},
				ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			},
		)
		require.NoError(t, err)

		err = svc.Unregister(connID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "router not registered")
	})

	t.Run("test unregister route - db error", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
				},
				StorageProviderValue: &mockstore.MockStoreProvider{
					Store: &mockstore.MockStore{Store: s, ErrGet: errors.New("get error")},
				},
				ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			},
		)
		require.NoError(t, err)

		err = svc.Unregister(connID)
		require.Error(t, err)
		require.EqualError(t, err, "ensure connection exists: get error")
	})
}

func TestKeylistUpdate(t *testing.T) {
	const connID = "conn-id"

	t.Run("test keylist update - success", func(t *testing.T) {
		keyUpdateMsg := make(chan KeylistUpdate)
		recKey := "ojaosdjoajs123jkas"

		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					request := &KeylistUpdate{}

					err := reqMsgMap.Decode(request)
					require.NoError(t, err)

					keyUpdateMsg <- *request
					return nil
				},
			},
		})
		require.NoError(t, err)

		// save router connID
		require.NoError(t, svc.saveRouterConnectionID("conn"))

		// save connections
		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "complete",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		s["conn_conn"] = mockstore.DBEntry{Value: connBytes}

		go func() {
			updateMsg := <-keyUpdateMsg

			updates := []UpdateResponse{
				{
					RecipientKey: updateMsg.Updates[0].RecipientKey,
					Action:       updateMsg.Updates[0].Action,
					Result:       success,
				},
			}
			require.NoError(t, svc.handleKeylistUpdateResponse(generateKeylistUpdateResponseMsgPayload(
				t, updateMsg.ID, updates)))
		}()

		err = svc.AddKey("conn", recKey)
		require.NoError(t, err)
	})

	t.Run("test keylist update - failure", func(t *testing.T) {
		keyUpdateMsg := make(chan KeylistUpdate)
		recKey := "ojaosdjoajs123jkas"

		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue: &mockdispatcher.MockOutbound{
				ValidateSendToDID: func(msg interface{}, myDID, theirDID string) error {
					require.Equal(t, myDID, MYDID)
					require.Equal(t, theirDID, THEIRDID)

					reqMsgMap, ok := msg.(service.DIDCommMsgMap)
					require.True(t, ok)

					request := &KeylistUpdate{}

					err := reqMsgMap.Decode(request)
					require.NoError(t, err)

					keyUpdateMsg <- *request
					return nil
				},
			},
		})
		require.NoError(t, err)

		// no router registered
		err = svc.AddKey(connID, recKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "router not registered")

		// save router connID
		require.NoError(t, svc.saveRouterConnectionID("conn"))

		// no connections saved
		err = svc.AddKey("conn", recKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection not found")

		// save connections
		connRec := &connection.Record{
			ConnectionID: "conn", MyDID: MYDID, TheirDID: THEIRDID, State: "complete",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		s["conn_conn"] = mockstore.DBEntry{Value: connBytes}

		go func() {
			updateMsg := <-keyUpdateMsg

			updates := []UpdateResponse{
				{
					RecipientKey: updateMsg.Updates[0].RecipientKey,
					Action:       updateMsg.Updates[0].Action,
					Result:       serverError,
				},
			}
			require.NoError(t, svc.handleKeylistUpdateResponse(generateKeylistUpdateResponseMsgPayload(
				t, updateMsg.ID, updates)))
		}()

		err = svc.AddKey("conn", recKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update the recipient key with the router")
	})

	t.Run("test keylist update - timeout error", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		connRec := &connection.Record{
			ConnectionID: "conn2", MyDID: MYDID, TheirDID: THEIRDID, State: "complete",
		}
		connBytes, err := json.Marshal(connRec)
		require.NoError(t, err)
		s["conn_conn2"] = mockstore.DBEntry{Value: connBytes}
		require.NoError(t, svc.saveRouterConnectionID("conn2"))

		err = svc.AddKey("conn2", "recKey")
		require.Error(t, err)
		require.Contains(t, err.Error(), "timeout waiting for keylist update response from the router")
	})

	t.Run("test keylist update - router connectionID fetch error", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{Store: s, ErrGet: errors.New("get error")},
			},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		err = svc.AddKey("conn", "recKey")
		require.Error(t, err)
		require.EqualError(t, err, "ensure connection exists: get error")
	})
}

func TestConfig(t *testing.T) {
	routingKeys := []string{"abc", "xyz"}

	t.Run("test config - success", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		require.NoError(t, svc.saveRouterConnectionID("connID-123"))
		require.NoError(t, svc.saveRouterConfig("connID-123", &config{
			RouterEndpoint: ENDPOINT,
			RoutingKeys:    routingKeys,
		}))

		conf, err := svc.Config("connID-123")
		require.NoError(t, err)
		require.Equal(t, ENDPOINT, conf.Endpoint())
		require.Equal(t, routingKeys, conf.Keys())
	})

	t.Run("test config - no router registered", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		conf, err := svc.Config("conn")
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrRouterNotRegistered))
		require.Nil(t, conf)
	})

	t.Run("test config - missing configs", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		require.NoError(t, svc.saveRouterConnectionID("connID-123"))

		conf, err := svc.Config("connID-123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get router config data")
		require.Nil(t, conf)
	})

	t.Run("test config - invalid config data in db", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue:              &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		const conn = "connID-123"

		require.NoError(t, svc.saveRouterConnectionID(conn))
		require.NoError(t, svc.routeStore.Put(fmt.Sprintf(routeConfigDataKey, conn), []byte("invalid data")))

		conf, err := svc.Config(conn)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal router config data")
		require.Nil(t, conf)
	})

	t.Run("test config - router connectionID fetch error", func(t *testing.T) {
		s := make(map[string]mockstore.DBEntry)
		svc, err := New(&mockprovider.Provider{
			ServiceMap: map[string]interface{}{
				messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
			},
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{Store: s, ErrGet: errors.New("get error")},
			},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			KMSValue:                          &mockkms.KeyManager{},
			OutboundDispatcherValue:           &mockdispatcher.MockOutbound{},
		})
		require.NoError(t, err)

		require.NoError(t, svc.saveRouterConnectionID("connID-123"))
		require.NoError(t, svc.routeStore.Put(routeConfigDataKey, []byte("invalid data")))

		conf, err := svc.Config("connID-123")
		require.Error(t, err)
		require.EqualError(t, err, "ensure connection exists: get error")
		require.Nil(t, conf)
	})
}

func TestGetConnections(t *testing.T) {
	routerConnectionID := "conn-abc-xyz"

	t.Run("test get connection - success", func(t *testing.T) {
		svc, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
				},
				StorageProviderValue:              mem.NewProvider(),
				ProtocolStateStorageProviderValue: mem.NewProvider(),
			},
		)
		require.NoError(t, err)

		err = svc.saveRouterConnectionID(routerConnectionID)
		require.NoError(t, err)

		connID, err := svc.GetConnections()
		require.NoError(t, err)
		require.Equal(t, routerConnectionID, connID[0])
	})

	t.Run("test get connection - no data found", func(t *testing.T) {
		svc, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickup.MessagePickup: &mockmessagep.MockMessagePickupSvc{},
				},
				StorageProviderValue:              mem.NewProvider(),
				ProtocolStateStorageProviderValue: mem.NewProvider(),
			},
		)
		require.NoError(t, err)

		connID, err := svc.GetConnections()
		require.NoError(t, err)
		require.Empty(t, connID)
	})
}

func generateRequestMsgPayload(t *testing.T, id string) service.DIDCommMsg {
	requestBytes, err := json.Marshal(&Request{
		Type: RequestMsgType,
		ID:   id,
	})
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(requestBytes)
	require.NoError(t, err)

	return didMsg
}

func generateGrantMsgPayload(t *testing.T, id string) service.DIDCommMsg {
	grantBytes, err := json.Marshal(&Grant{
		Type: GrantMsgType,
		ID:   id,
	})
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(grantBytes)
	require.NoError(t, err)

	return didMsg
}

func generateKeyUpdateListMsgPayload(t *testing.T, id string, updates []Update) service.DIDCommMsg {
	requestBytes, err := json.Marshal(&KeylistUpdate{
		Type:    KeylistUpdateMsgType,
		ID:      id,
		Updates: updates,
	})
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(requestBytes)
	require.NoError(t, err)

	return didMsg
}

func generateKeylistUpdateResponseMsgPayload(t *testing.T, id string, updates []UpdateResponse) service.DIDCommMsg {
	respBytes, err := json.Marshal(&KeylistUpdateResponse{
		Type:    KeylistUpdateResponseMsgType,
		ID:      id,
		Updated: updates,
	})
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(respBytes)
	require.NoError(t, err)

	return didMsg
}

func generateForwardMsgPayload(t *testing.T, id, to string, msg []byte) service.DIDCommMsg {
	requestBytes, err := json.Marshal(&model.Forward{
		Type: service.ForwardMsgType,
		ID:   id,
		To:   to,
		Msg:  msg,
	})
	require.NoError(t, err)

	didMsg, err := service.ParseDIDCommMsgMap(requestBytes)
	require.NoError(t, err)

	return didMsg
}

func randomID() string {
	return uuid.New().String()
}

type connectionsStub struct {
	getConnIDByDIDs func(string, string) (string, error)
	getConnRecord   func(string) (*connection.Record, error)
}

func (c *connectionsStub) GetConnectionRecordByDIDs(myDID, theirDID string) (*connection.Record, error) {
	connID, err := c.GetConnectionIDByDIDs(myDID, theirDID)
	if err != nil {
		return nil, err
	}

	return c.GetConnectionRecord(connID)
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
