/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	commonmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

func TestNoopState(t *testing.T) {
	noop := &noOp{}
	require.Equal(t, "noop", noop.Name())

	t.Run("must not transition to any state", func(t *testing.T) {
		all := []state{&null{}, &invited{}, &requested{}, &responded{}, &completed{}}
		for _, s := range all {
			require.False(t, noop.CanTransitionTo(s))
		}
	})
}

// null state can transition to invited state or requested state.
func TestNullState(t *testing.T) {
	nul := &null{}
	require.Equal(t, "null", nul.Name())
	require.False(t, nul.CanTransitionTo(nul))
	require.True(t, nul.CanTransitionTo(&invited{}))
	require.True(t, nul.CanTransitionTo(&requested{}))
	require.False(t, nul.CanTransitionTo(&responded{}))
	require.False(t, nul.CanTransitionTo(&completed{}))
}

// invited can only transition to requested state.
func TestInvitedState(t *testing.T) {
	inv := &invited{}
	require.Equal(t, "invited", inv.Name())
	require.False(t, inv.CanTransitionTo(&null{}))
	require.False(t, inv.CanTransitionTo(inv))
	require.True(t, inv.CanTransitionTo(&requested{}))
	require.False(t, inv.CanTransitionTo(&responded{}))
	require.False(t, inv.CanTransitionTo(&completed{}))
}

// requested can only transition to responded state.
func TestRequestedState(t *testing.T) {
	req := &requested{}
	require.Equal(t, "requested", req.Name())
	require.False(t, req.CanTransitionTo(&null{}))
	require.False(t, req.CanTransitionTo(&invited{}))
	require.False(t, req.CanTransitionTo(req))
	require.True(t, req.CanTransitionTo(&responded{}))
	require.False(t, req.CanTransitionTo(&completed{}))
}

// responded can only transition to completed state.
func TestRespondedState(t *testing.T) {
	res := &responded{}
	require.Equal(t, "responded", res.Name())
	require.False(t, res.CanTransitionTo(&null{}))
	require.False(t, res.CanTransitionTo(&invited{}))
	require.False(t, res.CanTransitionTo(&requested{}))
	require.False(t, res.CanTransitionTo(res))
	require.True(t, res.CanTransitionTo(&completed{}))
}

// completed is an end state.
func TestCompletedState(t *testing.T) {
	comp := &completed{}
	require.Equal(t, "completed", comp.Name())
	require.False(t, comp.CanTransitionTo(&null{}))
	require.False(t, comp.CanTransitionTo(&invited{}))
	require.False(t, comp.CanTransitionTo(&requested{}))
	require.False(t, comp.CanTransitionTo(&responded{}))
	require.False(t, comp.CanTransitionTo(comp))
}

func TestStateFromMsgType(t *testing.T) {
	t.Run("invited", func(t *testing.T) {
		expected := &invited{}
		actual, err := stateFromMsgType(InvitationMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("requested", func(t *testing.T) {
		expected := &requested{}
		actual, err := stateFromMsgType(RequestMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("responded", func(t *testing.T) {
		expected := &responded{}
		actual, err := stateFromMsgType(ResponseMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("completed", func(t *testing.T) {
		expected := &completed{}
		actual, err := stateFromMsgType(AckMsgType)
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("invalid", func(t *testing.T) {
		actual, err := stateFromMsgType("invalid")
		require.Nil(t, actual)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unrecognized msgType: invalid")
	})
}

func TestStateFromName(t *testing.T) {
	t.Run("noop", func(t *testing.T) {
		expected := &noOp{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("null", func(t *testing.T) {
		expected := &null{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("invited", func(t *testing.T) {
		expected := &invited{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("requested", func(t *testing.T) {
		expected := &requested{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("responded", func(t *testing.T) {
		expected := &responded{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("completed", func(t *testing.T) {
		expected := &completed{}
		actual, err := stateFromName(expected.Name())
		require.NoError(t, err)
		require.Equal(t, expected.Name(), actual.Name())
	})
	t.Run("undefined", func(t *testing.T) {
		actual, err := stateFromName("undefined")
		require.Nil(t, actual)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid state name")
	})
}

// noOp.ExecuteInbound() returns nil, error.
func TestNoOpState_Execute(t *testing.T) {
	_, followup, _, err := (&noOp{}).ExecuteInbound(&stateMachineMsg{}, "", &context{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot execute no-op")
	require.Nil(t, followup)
}

// null.ExecuteInbound() is a no-op.
func TestNullState_Execute(t *testing.T) {
	_, followup, _, err := (&null{}).ExecuteInbound(&stateMachineMsg{}, "", &context{})
	require.NoError(t, err)
	require.IsType(t, &noOp{}, followup)
}

func TestInvitedState_Execute(t *testing.T) {
	t.Run("rejects msgs other than invitations", func(t *testing.T) {
		others := []service.DIDCommMsg{
			service.NewDIDCommMsgMap(Request{Type: RequestMsgType}),
			service.NewDIDCommMsgMap(Response{Type: ResponseMsgType}),
			service.NewDIDCommMsgMap(model.Ack{Type: AckMsgType}),
		}
		for _, msg := range others {
			_, _, _, err := (&invited{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: msg,
			}, "", &context{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "illegal msg type")
		}
	})
	t.Run("followup to 'requested' on inbound invitations", func(t *testing.T) {
		invitationPayloadBytes, err := json.Marshal(&Invitation{
			Type:            InvitationMsgType,
			ID:              randomString(),
			Label:           "Bob",
			RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
			ServiceEndpoint: "https://localhost:8090",
			RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		})
		require.NoError(t, err)
		connRec, followup, _, err := (&invited{}).ExecuteInbound(
			&stateMachineMsg{
				DIDCommMsg: bytesToDIDCommMsg(t, invitationPayloadBytes),
				connRecord: &connection.Record{},
			},
			"",
			&context{})
		require.NoError(t, err)
		require.Equal(t, &requested{}, followup)
		require.NotNil(t, connRec)
	})
}

func TestRequestedState_Execute(t *testing.T) {
	prov := getProvider(t)
	// Alice receives an invitation from Bob
	invitationPayloadBytes, err := json.Marshal(&Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://localhost:8090",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	})
	require.NoError(t, err)

	mtps := []string{
		transport.MediaTypeRFC0019EncryptedEnvelope,
		transport.MediaTypeProfileDIDCommAIP1,
	}

	for _, mtp := range mtps {
		t.Run("rejects messages other than invitations or requests", func(t *testing.T) {
			others := []service.DIDCommMsg{
				service.NewDIDCommMsgMap(Response{Type: ResponseMsgType}),
				service.NewDIDCommMsgMap(model.Ack{Type: AckMsgType}),
			}
			for _, msg := range others {
				_, _, _, e := (&requested{}).ExecuteInbound(&stateMachineMsg{
					DIDCommMsg: msg,
				}, "", &context{})
				require.Error(t, e)
				require.Contains(t, e.Error(), "illegal msg type")
			}
		})
		t.Run("handle inbound invitations", func(t *testing.T) {
			ctx := getContext(t, &prov, mtp)
			msg, e := service.ParseDIDCommMsgMap(invitationPayloadBytes)
			require.NoError(t, e)
			thid, e := msg.ThreadID()
			require.NoError(t, e)
			connRec, _, _, e := (&requested{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: msg,
				connRecord: &connection.Record{},
			}, thid, ctx)
			require.NoError(t, e)
			require.NotNil(t, connRec.MyDID)
		})
		t.Run("handling invitations fails if my diddoc does not have a valid didcomm service", func(t *testing.T) {
			msg, e := service.ParseDIDCommMsgMap(invitationPayloadBytes)
			require.NoError(t, e)

			ctx := getContext(t, &prov, mtp)

			myDoc := createDIDDoc(t, ctx)
			myDoc.Service = []diddoc.Service{{
				ID:              uuid.New().String(),
				Type:            "invalid",
				Priority:        0,
				RecipientKeys:   nil,
				ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("https://localhost:8090"),
			}}
			ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: myDoc}
			_, _, _, err = (&requested{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: msg,
				connRecord: &connection.Record{},
			}, "", ctx)
			require.Error(t, err)
		})
		t.Run("inbound request unmarshalling error", func(t *testing.T) {
			_, followup, _, err := (&requested{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: service.DIDCommMsgMap{
					"@type": InvitationMsgType,
					"@id":   map[int]int{},
				},
			}, "", &context{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "JSON unmarshalling of invitation")
			require.Nil(t, followup)
		})
		t.Run("create DID error", func(t *testing.T) {
			ctx2 := &context{
				outboundDispatcher: prov.OutboundDispatcher(),
				vdRegistry:         &mockvdr.MockVDRegistry{CreateErr: fmt.Errorf("create DID error")},
			}
			didDoc, err := ctx2.vdRegistry.Create(testMethod, nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "create DID error")
			require.Nil(t, didDoc)
		})
	}
}

func TestRespondedState_Execute(t *testing.T) {
	mtps := []string{transport.MediaTypeProfileDIDCommAIP1, transport.MediaTypeRFC0019EncryptedEnvelope}

	for _, mtp := range mtps {
		prov := getProvider(t)
		ctx := getContext(t, &prov, mtp)

		request, err := createRequest(t, ctx)
		require.NoError(t, err)

		requestPayloadBytes, err := json.Marshal(request)
		require.NoError(t, err)

		response, err := createResponse(request, ctx)
		require.NoError(t, err)

		responsePayloadBytes, err := json.Marshal(response)
		require.NoError(t, err)

		t.Run("rejects messages other than requests and responses", func(t *testing.T) {
			others := []service.DIDCommMsg{
				service.NewDIDCommMsgMap(Invitation{Type: InvitationMsgType}),
				service.NewDIDCommMsgMap(model.Ack{Type: AckMsgType}),
			}
			for _, msg := range others {
				_, _, _, e := (&responded{}).ExecuteInbound(&stateMachineMsg{
					DIDCommMsg: msg,
				}, "", &context{})
				require.Error(t, e)
				require.Contains(t, e.Error(), "illegal msg type")
			}
		})
		t.Run("no followup for inbound requests", func(t *testing.T) {
			connRec, followup, _, e := (&responded{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: bytesToDIDCommMsg(t, requestPayloadBytes),
				connRecord: &connection.Record{},
			}, "", ctx)
			require.NoError(t, e)
			require.NotNil(t, connRec)
			require.IsType(t, &noOp{}, followup)
		})
		t.Run("followup to 'completed' on inbound responses", func(t *testing.T) {
			connRec := &connection.Record{
				State:        (&responded{}).Name(),
				ThreadID:     request.ID,
				ConnectionID: "123",
				Namespace:    findNamespace(ResponseMsgType),
			}
			err = ctx.connectionRecorder.SaveConnectionRecordWithMappings(connRec)
			require.NoError(t, err)
			connRec, followup, _, e := (&responded{}).ExecuteInbound(
				&stateMachineMsg{
					DIDCommMsg: bytesToDIDCommMsg(t, responsePayloadBytes),
					connRecord: connRec,
				}, "", ctx)
			require.NoError(t, e)
			require.NotNil(t, connRec)
			require.Equal(t, (&completed{}).Name(), followup.Name())
		})

		t.Run("handle inbound request unmarshalling error", func(t *testing.T) {
			_, followup, _, err := (&responded{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: service.DIDCommMsgMap{"@id": map[int]int{}, "@type": RequestMsgType},
			}, "", &context{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "JSON unmarshalling of request")
			require.Nil(t, followup)
		})

		t.Run("fails if my did has an invalid didcomm service entry", func(t *testing.T) {
			myDoc := createDIDDoc(t, ctx)
			myDoc.Service = []diddoc.Service{{
				ID:              uuid.New().String(),
				Type:            "invalid",
				Priority:        0,
				RecipientKeys:   nil,
				ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("http://localhost:58416"),
			}}
			ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: myDoc}
			_, _, _, err := (&responded{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: bytesToDIDCommMsg(t, requestPayloadBytes),
				connRecord: &connection.Record{},
			}, "", ctx)
			require.Error(t, err)
		})
	}
}

// completed is an end state.
func TestCompletedState_Execute(t *testing.T) {
	prov := getProvider(t)
	customKMS := newKMS(t, prov.StoreProvider)
	ctx := &context{
		crypto:           &tinkcrypto.Crypto{},
		kms:              customKMS,
		keyType:          kms.ED25519Type,
		keyAgreementType: kms.X25519ECDHKWType,
	}
	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	connRec, err := connection.NewRecorder(&prov)

	require.NoError(t, err)
	require.NotNil(t, connRec)

	ctx.connectionRecorder = connRec

	newDIDDoc := createDIDDocWithKey(pubKey)

	invitation, err := createMockInvitation(pubKey, ctx)
	require.NoError(t, err)

	connectionSignature, err := ctx.prepareConnectionSignature(newDIDDoc, invitation.RecipientKeys[0])
	require.NoError(t, err)

	response := &Response{
		Type:                ResponseMsgType,
		ID:                  randomString(),
		ConnectionSignature: connectionSignature,
		Thread: &decorator.Thread{
			ID: "test",
		},
		PleaseAck: &PleaseAck{On: []string{PlsAckOnReceipt}},
	}

	t.Run("no followup for inbound responses", func(t *testing.T) {
		var responsePayloadBytes []byte

		responsePayloadBytes, err = json.Marshal(response)
		require.NoError(t, err)

		newConnRec := &connection.Record{
			State:         (&responded{}).Name(),
			ThreadID:      response.Thread.ID,
			ConnectionID:  "123",
			MyDID:         "did:peer:123456789abcdefghi#inbox",
			Namespace:     myNSPrefix,
			InvitationID:  invitation.ID,
			RecipientKeys: []string{base58.Encode(pubKey)},
		}
		err = ctx.connectionRecorder.SaveConnectionRecordWithMappings(newConnRec)
		require.NoError(t, err)
		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: mockdiddoc.GetMockDIDDoc(t, false)}
		require.NoError(t, err)
		_, followup, _, e := (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: bytesToDIDCommMsg(t, responsePayloadBytes),
			connRecord: newConnRec,
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for inbound acks", func(t *testing.T) {
		newConnRec := &connection.Record{
			State:         (&responded{}).Name(),
			ThreadID:      response.Thread.ID,
			ConnectionID:  "123",
			Namespace:     findNamespace(AckMsgType),
			RecipientKeys: []string{base58.Encode(pubKey)},
		}
		err = ctx.connectionRecorder.SaveConnectionRecordWithMappings(newConnRec)
		require.NoError(t, err)
		ack := &model.Ack{
			Type:   AckMsgType,
			ID:     randomString(),
			Status: ackStatusOK,
			Thread: &decorator.Thread{
				ID: response.Thread.ID,
			},
		}
		ackPayloadBytes, e := json.Marshal(ack)
		require.NoError(t, e)
		_, followup, _, e := (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: bytesToDIDCommMsg(t, ackPayloadBytes),
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("rejects messages other than responses, acks, and completes", func(t *testing.T) {
		others := []service.DIDCommMsg{
			service.NewDIDCommMsgMap(Invitation{Type: InvitationMsgType}),
			service.NewDIDCommMsgMap(Request{Type: RequestMsgType}),
		}

		for _, msg := range others {
			_, _, _, err = (&completed{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: msg,
			}, "", &context{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "illegal msg type")
		}
	})
	t.Run("no followup for inbound responses unmarshalling error", func(t *testing.T) {
		_, followup, _, err := (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: service.DIDCommMsgMap{"@id": map[int]int{}, "@type": ResponseMsgType},
		}, "", &context{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "JSON unmarshalling of response")
		require.Nil(t, followup)
	})

	t.Run("execute inbound handle inbound response error", func(t *testing.T) {
		response.ConnectionSignature = &ConnectionSignature{}
		responsePayloadBytes, err := json.Marshal(response)
		require.NoError(t, err)

		_, followup, _, err := (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: bytesToDIDCommMsg(t, responsePayloadBytes),
		}, "", ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "handle inbound response")
		require.Nil(t, followup)
	})
}

func TestNewRequestFromInvitation(t *testing.T) {
	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
		ServiceEndpoint: "https://localhost:8090",
		RoutingKeys:     []string{"8HH5gYEeNc3z7PYXmd54d4x6qAfCNrqQqEB3nS7Zfu7K"},
	}

	t.Run("successful new request from invitation", func(t *testing.T) {
		prov := getProvider(t)
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)
		_, connRec, err := ctx.handleInboundInvitation(invitation, invitation.ID, &options{}, &connection.Record{})
		require.NoError(t, err)
		require.NotNil(t, connRec.MyDID)
	})
	t.Run("successful response to invitation with public did", func(t *testing.T) {
		prov := getProvider(t)
		ctx := &context{
			kms:               prov.CustomKMS,
			keyType:           kms.ED25519Type,
			keyAgreementType:  kms.X25519ECDHKWType,
			mediaTypeProfiles: []string{transport.MediaTypeRFC0019EncryptedEnvelope},
		}
		doc := createDIDDoc(t, ctx)
		connRec, err := connection.NewRecorder(&protocol.MockProvider{})
		require.NoError(t, err)
		didConnStore, err := didstore.NewConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)

		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: doc}
		ctx.connectionRecorder = connRec
		ctx.connectionStore = didConnStore

		_, connRecord, err := ctx.handleInboundInvitation(invitation, invitation.ID, &options{publicDID: doc.ID},
			&connection.Record{})
		require.NoError(t, err)
		require.NotNil(t, connRecord.MyDID)
		require.Equal(t, connRecord.MyDID, doc.ID)
	})
	t.Run("unsuccessful new request from invitation ", func(t *testing.T) {
		prov := protocol.MockProvider{}
		customKMS := newKMS(t, mem.NewProvider())

		ctx := &context{
			kms:                customKMS,
			outboundDispatcher: prov.OutboundDispatcher(),
			routeSvc:           &mockroute.MockMediatorSvc{},
			vdRegistry:         &mockvdr.MockVDRegistry{CreateErr: fmt.Errorf("create DID error")},
			keyType:            kms.ED25519Type,
			keyAgreementType:   kms.X25519ECDHKWType,
			mediaTypeProfiles:  []string{transport.MediaTypeRFC0019EncryptedEnvelope},
		}
		_, connRec, err := ctx.handleInboundInvitation(invitation, invitation.ID, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create DID error")
		require.Nil(t, connRec)
	})
}

func TestNewResponseFromRequest(t *testing.T) {
	prov := getProvider(t)
	store := mockstorage.NewMockStoreProvider()
	k := newKMS(t, store)

	t.Run("successful new response from request", func(t *testing.T) {
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)
		request, err := createRequest(t, ctx)
		require.NoError(t, err)
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.NoError(t, err)
		require.NotNil(t, connRec.MyDID)
		require.NotNil(t, connRec.TheirDID)
	})

	t.Run("unsuccessful new response from request due to resolve DID error", func(t *testing.T) {
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)
		request, err := createRequest(t, ctx)
		require.NoError(t, err)

		request.Connection.DID = "did:invalid"
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve did doc from connection request")
		require.Nil(t, connRec)
	})

	t.Run("unsuccessful new response from request due to create did error", func(t *testing.T) {
		didDoc := mockdiddoc.GetMockDIDDoc(t, false)
		ctx := &context{
			vdRegistry: &mockvdr.MockVDRegistry{
				CreateErr:    fmt.Errorf("create DID error"),
				ResolveValue: mockdiddoc.GetMockDIDDoc(t, false),
			},
			routeSvc: &mockroute.MockMediatorSvc{},
		}
		request := &Request{
			Connection: &Connection{
				DID:    didDoc.ID,
				DIDDoc: didDoc,
			},
		}
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create DID error")
		require.Nil(t, connRec)
	})

	t.Run("unsuccessful new response from request due to get did doc error", func(t *testing.T) {
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.connectionStore = &mockConnectionStore{saveDIDFromDocErr: fmt.Errorf("save did error")}

		request, err := createRequest(t, ctx)
		require.NoError(t, err)
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get response did doc and connection")
		require.Nil(t, connRec)
	})

	t.Run("prepare connection signature get invitation", func(t *testing.T) {
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)

		request, err := createRequest(t, ctx)
		request.Thread.PID = "test"

		require.NoError(t, err)
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)

		require.Contains(t, err.Error(), "get invitation for [invitationID=test]: data not found")
		require.Nil(t, connRec)
	})

	t.Run("prepare connection signature get invitation", func(t *testing.T) {
		invID := randomString()
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)

		request, err := createRequest(t, ctx)
		request.Thread.PID = invID

		require.NoError(t, err)
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)

		require.Contains(t, err.Error(), fmt.Sprintf("get invitation for [invitationID=%s]: data not found", invID))
		require.Nil(t, connRec)
	})

	t.Run("unsuccessful new response from request due to sign error", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&prov)
		require.NoError(t, err)
		require.NotNil(t, connRec)

		didConnStore, err := didstore.NewConnectionStore(&prov)
		require.NoError(t, err)
		require.NotNil(t, didConnStore)

		ctx := &context{
			vdRegistry:         &mockvdr.MockVDRegistry{CreateValue: mockdiddoc.GetMockDIDDoc(t, false)},
			crypto:             &mockcrypto.Crypto{SignErr: errors.New("sign error")},
			connectionRecorder: connRec,
			connectionStore:    didConnStore,
			routeSvc:           &mockroute.MockMediatorSvc{},
			kms:                prov.CustomKMS,
			keyType:            kms.ED25519Type,
			keyAgreementType:   kms.X25519ECDHKWType,
			doACAPyInterop:     true,
		}

		request, err := createRequest(t, ctx)
		require.NoError(t, err)

		_, connRecord, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "sign error")
		require.Nil(t, connRecord)
	})

	t.Run("unsuccessful new response from request due to resolve public did from request error", func(t *testing.T) {
		ctx := &context{vdRegistry: &mockvdr.MockVDRegistry{ResolveErr: errors.New("resolver error")}}
		request := &Request{Connection: &Connection{DID: "did:sidetree:abc", DIDDoc: &diddoc.Doc{}}}
		_, _, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolver error")
	})

	t.Run("unsuccessful new response from request due to invalid did for creating destination", func(t *testing.T) {
		mockDoc := newPeerDID(t, k)
		mockDoc.Service = nil

		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)

		request, err := createRequest(t, ctx)
		require.NoError(t, err)

		request.Connection.DID = mockDoc.ID
		request.Connection.DIDDoc = mockDoc

		_, _, err = ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
	})
}

func TestPrepareConnectionSignature(t *testing.T) {
	prov := getProvider(t)
	ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)

	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invitation, err := createMockInvitation(pubKey, ctx)
	require.NoError(t, err)

	doc, err := ctx.vdRegistry.Create(testMethod, nil)
	require.NoError(t, err)

	t.Run("prepare connection signature", func(t *testing.T) {
		connectionSignature, err := ctx.prepareConnectionSignature(doc.DIDDocument, invitation.RecipientKeys[0])
		require.NoError(t, err)
		require.NotNil(t, connectionSignature)
		sigData, err := base64.URLEncoding.DecodeString(connectionSignature.SignedData)
		require.NoError(t, err)
		connBytes := sigData[timestampLength:]
		sigDataConnection := &Connection{}
		err = json.Unmarshal(connBytes, sigDataConnection)
		require.NoError(t, err)
		require.Equal(t, doc.DIDDocument.ID, sigDataConnection.DID)
	})
	t.Run("implicit invitation with DID - success", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&prov)
		require.NoError(t, err)
		require.NotNil(t, connRec)

		didConnStore, err := didstore.NewConnectionStore(&prov)
		require.NoError(t, err)
		require.NotNil(t, didConnStore)

		connectionSignature, err := ctx.prepareConnectionSignature(doc.DIDDocument, invitation.RecipientKeys[0])
		require.NoError(t, err)
		require.NotNil(t, connectionSignature)
		sigData, err := base64.URLEncoding.DecodeString(connectionSignature.SignedData)
		require.NoError(t, err)
		connBytes := sigData[timestampLength:]
		sigDataConnection := &Connection{}
		err = json.Unmarshal(connBytes, sigDataConnection)
		require.NoError(t, err)
		require.Equal(t, doc.DIDDocument.ID, sigDataConnection.DID)
	})
	t.Run("prepare connection signature error", func(t *testing.T) {
		ctx2 := ctx
		ctx2.crypto = &mockcrypto.Crypto{SignErr: errors.New("sign error")}
		newDIDDoc := mockdiddoc.GetMockDIDDoc(t, false)

		connectionSignature, err := ctx2.prepareConnectionSignature(newDIDDoc, invitation.RecipientKeys[0])
		require.Error(t, err)
		require.Contains(t, err.Error(), "sign error")
		require.Nil(t, connectionSignature)
	})
}

func TestVerifySignature(t *testing.T) {
	prov := getProvider(t)

	ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)

	keyID, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	newDIDDoc := createDIDDocWithKey(pubKey)

	invitation, err := createMockInvitation(pubKey, ctx)
	require.NoError(t, err)

	t.Run("signature verified", func(t *testing.T) {
		connectionSignature, err := ctx.prepareConnectionSignature(newDIDDoc, invitation.RecipientKeys[0])
		require.NoError(t, err)
		con, err := ctx.verifySignature(connectionSignature, invitation.RecipientKeys[0])
		require.NoError(t, err)
		require.NotNil(t, con)
		require.Equal(t, newDIDDoc.ID, con.DID)
	})
	t.Run("missing/invalid signature data", func(t *testing.T) {
		con, err := ctx.verifySignature(&ConnectionSignature{}, invitation.RecipientKeys[0])
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing or invalid signature data")
		require.Nil(t, con)
	})
	t.Run("decode signature data error", func(t *testing.T) {
		connectionSignature, err := ctx.prepareConnectionSignature(newDIDDoc, invitation.RecipientKeys[0])
		require.NoError(t, err)

		connectionSignature.SignedData = "invalid-signed-data"
		con, err := ctx.verifySignature(connectionSignature, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode signature data: illegal base64 data")
		require.Nil(t, con)
	})
	t.Run("decode signature error", func(t *testing.T) {
		connectionSignature, err := ctx.prepareConnectionSignature(newDIDDoc, invitation.RecipientKeys[0])
		require.NoError(t, err)

		connectionSignature.Signature = "invalid-signature"
		con, err := ctx.verifySignature(connectionSignature, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode signature: illegal base64 data")
		require.Nil(t, con)
	})
	t.Run("decode verification key error", func(t *testing.T) {
		connectionSignature, err := ctx.prepareConnectionSignature(newDIDDoc, invitation.RecipientKeys[0])
		require.NoError(t, err)

		con, err := ctx.verifySignature(connectionSignature, "invalid-key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get key handle: pubKey is empty")
		require.Nil(t, con)
	})
	t.Run("verify signature error", func(t *testing.T) {
		connectionSignature, err := ctx.prepareConnectionSignature(newDIDDoc, invitation.RecipientKeys[0])
		require.NoError(t, err)

		// generate different key and assign it to signature verification key
		pubKey2, _ := generateKeyPair()
		con, err := ctx.verifySignature(connectionSignature, pubKey2)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
		require.Nil(t, con)
	})
	t.Run("connection unmarshal error", func(t *testing.T) {
		connAttributeBytes := []byte("{hello world}")

		now := getEpochTime()
		timestampBuf := make([]byte, timestampLength)
		binary.BigEndian.PutUint64(timestampBuf, uint64(now))
		concatenateSignData := append(timestampBuf, connAttributeBytes...)

		kh, err := ctx.kms.Get(keyID)
		require.NoError(t, err)

		signature, err := ctx.crypto.Sign(concatenateSignData, kh)
		require.NoError(t, err)

		cs := &ConnectionSignature{
			Type:       "https://didcomm.org/signature/1.0/ed25519Sha512_single",
			SignedData: base64.URLEncoding.EncodeToString(concatenateSignData),
			SignVerKey: base64.URLEncoding.EncodeToString(pubKey),
			Signature:  base64.URLEncoding.EncodeToString(signature),
		}

		con, err := ctx.verifySignature(cs, invitation.RecipientKeys[0])
		require.Error(t, err)
		require.Contains(t, err.Error(), "JSON unmarshalling of connection")
		require.Nil(t, con)
	})
	t.Run("missing connection attribute bytes", func(t *testing.T) {
		now := getEpochTime()
		timestampBuf := make([]byte, timestampLength)
		binary.BigEndian.PutUint64(timestampBuf, uint64(now))

		kh, err := ctx.kms.Get(keyID)
		require.NoError(t, err)

		signature, err := ctx.crypto.Sign(timestampBuf, kh)
		require.NoError(t, err)

		cs := &ConnectionSignature{
			Type:       "https://didcomm.org/signature/1.0/ed25519Sha512_single",
			SignedData: base64.URLEncoding.EncodeToString(timestampBuf),
			SignVerKey: base64.URLEncoding.EncodeToString(pubKey),
			Signature:  base64.URLEncoding.EncodeToString(signature),
		}

		con, err := ctx.verifySignature(cs, invitation.RecipientKeys[0])
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing connection attribute bytes")
		require.Nil(t, con)
	})
}

func TestResolveDIDDocFromConnection(t *testing.T) {
	prov := getProvider(t)
	mtps := []string{transport.MediaTypeProfileDIDCommAIP1, transport.MediaTypeRFC0019EncryptedEnvelope}

	for _, mtp := range mtps {
		t.Run(fmt.Sprintf("success with media type profile: %s", mtp), func(t *testing.T) {
			ctx := getContext(t, &prov, mtp)
			docIn := mockdiddoc.GetMockDIDDoc(t, false)
			con := &Connection{
				DID:    docIn.ID,
				DIDDoc: docIn,
			}
			doc, err := ctx.resolveDidDocFromConnection(con)
			require.NoError(t, err)

			require.Equal(t, docIn.ID, doc.ID)
		})

		t.Run(fmt.Sprintf("success - public resolution with media type profile: %s", mtp), func(t *testing.T) {
			ctx := getContext(t, &prov, mtp)
			docIn := mockdiddoc.GetMockDIDDoc(t, false)
			docIn.ID = "did:remote:abc"

			ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: docIn}

			con := &Connection{
				DID:    docIn.ID,
				DIDDoc: docIn,
			}
			doc, err := ctx.resolveDidDocFromConnection(con)
			require.NoError(t, err)

			require.Equal(t, docIn.ID, doc.ID)
		})

		t.Run(fmt.Sprintf("failure - can't do public resolution with media type profile: %s", mtp),
			func(t *testing.T) {
				ctx := getContext(t, &prov, mtp)
				docIn := mockdiddoc.GetMockDIDDoc(t, false)
				docIn.ID = "did:remote:abc"

				ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf("resolve error")}

				con := &Connection{
					DID:    docIn.ID,
					DIDDoc: docIn,
				}
				_, err := ctx.resolveDidDocFromConnection(con)
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to resolve public did")
			})

		t.Run(fmt.Sprintf("failure - missing attachment for private did with media type profile: %s", mtp),
			func(t *testing.T) {
				ctx := getContext(t, &prov, mtp)
				_, err := ctx.resolveDidDocFromConnection(&Connection{DID: "did:peer:abcdefg"})
				require.Error(t, err)
				require.Contains(t, err.Error(), "missing DIDDoc")
			})

		t.Run(fmt.Sprintf("failure - can't store document locally with media type profile: %s", mtp),
			func(t *testing.T) {
				ctx := getContext(t, &prov, mtp)

				ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateErr: fmt.Errorf("create error")}

				docIn := mockdiddoc.GetMockDIDDoc(t, false)

				con := &Connection{
					DID:    docIn.ID,
					DIDDoc: docIn,
				}
				_, err := ctx.resolveDidDocFromConnection(con)
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to store provided did document")
			})
	}
}

func TestHandleInboundResponse(t *testing.T) {
	prov := getProvider(t)
	ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)
	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	_, err = createMockInvitation(pubKey, ctx)
	require.NoError(t, err)

	t.Run("handle inbound responses get connection record error", func(t *testing.T) {
		response := &Response{Thread: &decorator.Thread{ID: "test"}}
		_, connRec, e := ctx.handleInboundResponse(response)
		require.Error(t, e)
		require.Contains(t, e.Error(), "get connection record")
		require.Nil(t, connRec)
	})
	t.Run("handle inbound responses get connection record error", func(t *testing.T) {
		response := &Response{Thread: &decorator.Thread{ID: ""}}
		_, connRec, e := ctx.handleInboundResponse(response)
		require.Error(t, e)
		require.Contains(t, e.Error(), "empty bytes")
		require.Nil(t, connRec)
	})
}

func TestGetInvitationRecipientKey(t *testing.T) {
	prov := getProvider(t)
	ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)

	t.Run("successfully getting invitation recipient key", func(t *testing.T) {
		invitation := &Invitation{
			Type:            InvitationMsgType,
			ID:              randomString(),
			Label:           "Bob",
			RecipientKeys:   []string{"test"},
			ServiceEndpoint: "http://alice.agent.example.com:8081",
		}
		recKey, err := ctx.getInvitationRecipientKey(invitation)
		require.NoError(t, err)
		require.Equal(t, invitation.RecipientKeys[0], recKey)
	})
	t.Run("failed to get invitation recipient key", func(t *testing.T) {
		doc := mockdiddoc.GetMockDIDDoc(t, false)
		_, ok := diddoc.LookupService(doc, "did-communication")
		require.True(t, ok)

		ctx := context{vdRegistry: &mockvdr.MockVDRegistry{ResolveValue: doc}}
		invitation := &Invitation{
			Type: InvitationMsgType,
			ID:   randomString(),
			DID:  doc.ID,
		}

		recKey, err := ctx.getInvitationRecipientKey(invitation)
		require.NoError(t, err)
		require.Equal(t, doc.Service[0].RecipientKeys[0], recKey)
	})
	t.Run("failed to get invitation recipient key", func(t *testing.T) {
		invitation := &Invitation{
			Type: InvitationMsgType,
			ID:   randomString(),
			DID:  "test",
		}
		_, err := ctx.getInvitationRecipientKey(invitation)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get invitation recipient key: DID does not exist")
	})
}

func TestGetPublicKey(t *testing.T) {
	k := newKMS(t, mockstorage.NewMockStoreProvider())
	t.Run("successfully getting public key by id", func(t *testing.T) {
		prov := protocol.MockProvider{CustomKMS: k}
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)
		doc, err := ctx.vdRegistry.Create(testMethod, nil)
		require.NoError(t, err)
		pubkey, ok := diddoc.LookupPublicKey(doc.DIDDocument.VerificationMethod[0].ID, doc.DIDDocument)
		require.True(t, ok)
		require.NotNil(t, pubkey)
	})
	t.Run("failed to get public key", func(t *testing.T) {
		prov := protocol.MockProvider{CustomKMS: k}
		ctx := getContext(t, &prov, transport.MediaTypeRFC0019EncryptedEnvelope)
		doc, err := ctx.vdRegistry.Create(testMethod, nil)
		require.NoError(t, err)
		pubkey, ok := diddoc.LookupPublicKey("invalid-key", doc.DIDDocument)
		require.False(t, ok)
		require.Nil(t, pubkey)
	})
}

func TestGetDIDDocAndConnection(t *testing.T) {
	k := newKMS(t, mockstorage.NewMockStoreProvider())
	ctx := &context{
		kms:               k,
		keyType:           kms.ED25519Type,
		keyAgreementType:  kms.X25519ECDHKWType,
		mediaTypeProfiles: []string{transport.MediaTypeRFC0019EncryptedEnvelope},
	}

	t.Run("successfully getting did doc and connection for public did", func(t *testing.T) {
		doc := createDIDDoc(t, ctx)
		connRec, err := connection.NewRecorder(&protocol.MockProvider{})
		require.NoError(t, err)
		didConnStore, err := didstore.NewConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		ctx := context{
			vdRegistry:         &mockvdr.MockVDRegistry{ResolveValue: doc},
			connectionRecorder: connRec,
			connectionStore:    didConnStore,
		}
		didDoc, err := ctx.getMyDIDDoc(doc.ID, nil, "")
		require.NoError(t, err)
		require.NotNil(t, didDoc)
	})
	t.Run("error getting public did doc from resolver", func(t *testing.T) {
		ctx := context{
			vdRegistry: &mockvdr.MockVDRegistry{ResolveErr: errors.New("resolver error")},
		}
		didDoc, err := ctx.getMyDIDDoc("did-id", nil, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolver error")
		require.Nil(t, didDoc)
	})
	t.Run("error creating peer did", func(t *testing.T) {
		customKMS := newKMS(t, mockstorage.NewMockStoreProvider())
		ctx := context{
			kms:              customKMS,
			vdRegistry:       &mockvdr.MockVDRegistry{CreateErr: errors.New("creator error")},
			routeSvc:         &mockroute.MockMediatorSvc{},
			keyType:          kms.ED25519Type,
			keyAgreementType: kms.X25519ECDHKWType,
		}
		didDoc, err := ctx.getMyDIDDoc("", nil, didCommServiceType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "creator error")
		require.Nil(t, didDoc)
	})
	t.Run("error creating peer did with DIDCommV2 service type", func(t *testing.T) {
		customKMS := newKMS(t, mockstorage.NewMockStoreProvider())
		ctx := context{
			kms:              customKMS,
			vdRegistry:       &mockvdr.MockVDRegistry{CreateErr: errors.New("DIDCommMessaging is not supported")},
			routeSvc:         &mockroute.MockMediatorSvc{},
			keyType:          kms.ED25519Type,
			keyAgreementType: kms.X25519ECDHKWType,
		}
		didDoc, err := ctx.getMyDIDDoc("", nil, vdrapi.DIDCommV2ServiceType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DIDCommMessaging is not supported")
		require.Nil(t, didDoc)
	})
	t.Run("error creating peer did with empty service type", func(t *testing.T) {
		customKMS := newKMS(t, mockstorage.NewMockStoreProvider())
		ctx := context{
			kms:              customKMS,
			vdRegistry:       &mockvdr.MockVDRegistry{CreateErr: errors.New("is not supported")},
			routeSvc:         &mockroute.MockMediatorSvc{},
			keyType:          kms.ED25519Type,
			keyAgreementType: kms.X25519ECDHKWType,
		}
		didDoc, err := ctx.getMyDIDDoc("", nil, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "is not supported")
		require.Nil(t, didDoc)
	})

	t.Run("successfully created peer did", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&protocol.MockProvider{})
		require.NoError(t, err)
		didConnStore, err := didstore.NewConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		customKMS := newKMS(t, mockstorage.NewMockStoreProvider())
		ctx := context{
			kms:                customKMS,
			vdRegistry:         &mockvdr.MockVDRegistry{CreateValue: mockdiddoc.GetMockDIDDoc(t, false)},
			connectionRecorder: connRec,
			connectionStore:    didConnStore,
			routeSvc:           &mockroute.MockMediatorSvc{},
			keyType:            kms.ED25519Type,
			keyAgreementType:   kms.X25519ECDHKWType,
		}
		didDoc, err := ctx.getMyDIDDoc("", nil, didCommServiceType)
		require.NoError(t, err)
		require.NotNil(t, didDoc)
	})
	t.Run("test create did doc - router service config error", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&protocol.MockProvider{})
		require.NoError(t, err)
		customKMS := newKMS(t, mockstorage.NewMockStoreProvider())
		ctx := context{
			kms:                customKMS,
			vdRegistry:         &mockvdr.MockVDRegistry{CreateValue: mockdiddoc.GetMockDIDDoc(t, false)},
			connectionRecorder: connRec,
			routeSvc: &mockroute.MockMediatorSvc{
				Connections: []string{"xyz"},
				ConfigErr:   errors.New("router config error"),
			},
		}
		didDoc, err := ctx.getMyDIDDoc("", []string{"xyz"}, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did doc - fetch router config")
		require.Nil(t, didDoc)
	})

	t.Run("test create did doc - router service config error", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&protocol.MockProvider{})
		require.NoError(t, err)
		customKMS := newKMS(t, mockstorage.NewMockStoreProvider())
		ctx := context{
			kms: customKMS,
			vdRegistry: &mockvdr.MockVDRegistry{
				CreateValue: mockdiddoc.GetLegacyInteropMockDIDDoc(t, "1234567abcdefg", []byte("key")),
			},
			connectionRecorder: connRec,
			routeSvc: &mockroute.MockMediatorSvc{
				Connections: []string{"xyz"},
				AddKeyErr:   errors.New("router add key error"),
			},
			keyType:          kms.ED25519Type,
			keyAgreementType: kms.X25519ECDHKWType,
		}
		didDoc, err := ctx.getMyDIDDoc("", []string{"xyz"}, legacyDIDCommServiceType)
		require.Error(t, err)
		require.Contains(t, err.Error(), "did doc - add key to the router")
		require.Nil(t, didDoc)
	})
}

func TestGetVerKey(t *testing.T) {
	k := newKMS(t, mockstorage.NewMockStoreProvider())
	ctx := &context{
		kms:               k,
		keyType:           kms.ED25519Type,
		keyAgreementType:  kms.X25519ECDHKWType,
		mediaTypeProfiles: []string{transport.MediaTypeRFC0019EncryptedEnvelope},
	}

	t.Run("returns verkey from explicit connection invitation", func(t *testing.T) {
		expected := newServiceBlock()
		invitation := newConnectionInvite(t, "", expected)
		ctx.connectionRecorder = connRecorder(t, testProvider())

		err := ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
		require.NoError(t, err)

		result, err := ctx.getVerKey(invitation.ID)
		require.NoError(t, err)
		require.Equal(t, expected.RecipientKeys[0], result)

		expected = newServiceBlock()
		invitation = newConnectionInvite(t, "", expected)
		ctx.connectionRecorder = connRecorder(t, testProvider())

		err = ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
		require.NoError(t, err)

		result, err = ctx.getVerKey(invitation.ID)
		require.NoError(t, err)
		require.Equal(t, expected.RecipientKeys[0], result)
	})

	t.Run("returns verkey from implicit connection invitation", func(t *testing.T) {
		publicDID := createDIDDoc(t, ctx)
		ctx.connectionRecorder = connRecorder(t, testProvider())
		ctx.vdRegistry = &mockvdr.MockVDRegistry{
			ResolveValue: publicDID,
		}

		svc, found := diddoc.LookupService(publicDID, "did-communication")
		require.True(t, found)

		result, err := ctx.getVerKey(publicDID.ID)
		require.NoError(t, err)
		require.Equal(t, svc.RecipientKeys[0], result)
	})

	t.Run("wraps error from store", func(t *testing.T) {
		expected := errors.New("test")
		pr := testProvider()
		pr.StoreProvider = &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store:  make(map[string]mockstorage.DBEntry),
				ErrGet: expected,
			},
		}
		ctx.connectionRecorder = connRecorder(t, pr)

		_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		invitation, err := createMockInvitation(pubKey, ctx)
		require.NoError(t, err)

		err = ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
		require.NoError(t, err)

		_, err = ctx.getVerKey(invitation.ID)
		require.Error(t, err)
	})

	t.Run("wraps error from vdr resolution", func(t *testing.T) {
		expected := errors.New("test")
		ctx.connectionRecorder = connRecorder(t, testProvider())
		ctx.vdRegistry = &mockvdr.MockVDRegistry{
			ResolveErr: expected,
		}

		_, err := ctx.getVerKey("did:example:123")
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func createDIDDoc(t *testing.T, ctx *context) *diddoc.Doc {
	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	return createDIDDocWithKey(pubKey)
}

func createDIDDocWithKey(pubKey []byte) *diddoc.Doc {
	const (
		didFormat    = "did:%s:%s"
		didPKID      = "%s#keys-%d"
		didServiceID = "%s#endpoint-%d"
		method       = "test"
	)

	pub := base58.Encode(pubKey)
	id := fmt.Sprintf(didFormat, method, pub[:16])
	pubKeyID := fmt.Sprintf(didPKID, id, 1)
	verPubKeyVM := diddoc.VerificationMethod{
		ID:         pubKeyID,
		Type:       "Ed25519VerificationKey2018",
		Controller: id,
		Value:      pubKey,
	}
	services := []diddoc.Service{
		{
			ID:              fmt.Sprintf(didServiceID, id, 1),
			Type:            vdrapi.DIDCommServiceType,
			ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("http://localhost:58416"),
			Priority:        0,
			RecipientKeys:   []string{pubKeyID},
		},
	}

	services[0].Accept = []string{transport.MediaTypeRFC0019EncryptedEnvelope}

	createdTime := time.Now()
	didDoc := &diddoc.Doc{
		Context:            []string{diddoc.ContextV1},
		ID:                 id,
		VerificationMethod: []diddoc.VerificationMethod{verPubKeyVM},
		Service:            services,
		Created:            &createdTime,
		Updated:            &createdTime,
	}

	return didDoc
}

func getProvider(t *testing.T) protocol.MockProvider {
	t.Helper()

	store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}
	sProvider := mockstorage.NewCustomMockStoreProvider(store)
	customKMS := newKMS(t, sProvider)

	return protocol.MockProvider{
		StoreProvider: sProvider,
		CustomKMS:     customKMS,
	}
}

func getContext(t *testing.T, prov *protocol.MockProvider, mediaTypeProfile string) *context {
	t.Helper()

	ctx := &context{
		outboundDispatcher: prov.OutboundDispatcher(),
		crypto:             &tinkcrypto.Crypto{},
		routeSvc:           &mockroute.MockMediatorSvc{},
		kms:                prov.KMS(),
		keyType:            kms.ED25519Type,
		keyAgreementType:   kms.X25519ECDHKWType,
		mediaTypeProfiles:  []string{mediaTypeProfile},
	}

	connRec, err := connection.NewRecorder(prov)
	require.NoError(t, err)

	didConnStore, err := didstore.NewConnectionStore(prov)
	require.NoError(t, err)

	ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: createDIDDoc(t, ctx)}
	ctx.connectionRecorder = connRec
	ctx.connectionStore = didConnStore

	return ctx
}

func createRequest(t *testing.T, ctx *context) (*Request, error) {
	t.Helper()

	_, pubKey, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	invitation, err := createMockInvitation(pubKey, ctx)
	if err != nil {
		return nil, err
	}

	newDidDoc := createDIDDocWithKey(pubKey)

	// Prepare connection inbound request
	request := &Request{
		Type:  RequestMsgType,
		ID:    randomString(),
		Label: "Bob",
		Thread: &decorator.Thread{
			PID: invitation.ID,
		},
		Connection: &Connection{
			DID:    newDidDoc.ID,
			DIDDoc: newDidDoc,
		},
	}

	return request, nil
}

func generateKeyPair() (string, []byte) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return base58.Encode(pubKey[:]), privKey
}

func createResponse(request *Request, ctx *context) (*Response, error) {
	doc, err := ctx.vdRegistry.Create(testMethod, nil)
	if err != nil {
		return nil, err
	}

	verKey, err := ctx.getVerKey(request.Thread.PID)
	if err != nil {
		return nil, err
	}

	connectionSignature, err := ctx.prepareConnectionSignature(doc.DIDDocument, verKey)
	if err != nil {
		return nil, err
	}

	response := &Response{
		Type: ResponseMsgType,
		ID:   randomString(),
		Thread: &decorator.Thread{
			ID: request.ID,
		},
		ConnectionSignature: connectionSignature,
		PleaseAck: &PleaseAck{
			On: []string{PlsAckOnReceipt},
		},
	}

	return response, nil
}

func createMockInvitation(pubKey []byte, ctx *context) (*Invitation, error) {
	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{base58.Encode(pubKey)},
		ServiceEndpoint: "http://alice.agent.example.com:8081",
	}

	err := ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
	if err != nil {
		return nil, err
	}

	return invitation, nil
}

func toDIDCommMsg(t *testing.T, v interface{}) service.DIDCommMsgMap {
	msg, err := service.ParseDIDCommMsgMap(toBytes(t, v))
	require.NoError(t, err)

	return msg
}

func bytesToDIDCommMsg(t *testing.T, v []byte) service.DIDCommMsg {
	msg, err := service.ParseDIDCommMsgMap(v)
	require.NoError(t, err)

	return msg
}

func toBytes(t *testing.T, data interface{}) []byte {
	t.Helper()

	src, err := json.Marshal(data)
	require.NoError(t, err)

	return src
}

func newConnectionInvite(t *testing.T, publicDID string, svc *diddoc.Service) *Invitation {
	t.Helper()

	i := &Invitation{
		ID:   uuid.New().String(),
		Type: InvitationMsgType,
		DID:  publicDID,
	}

	if svc != nil {
		var err error

		i.RecipientKeys = svc.RecipientKeys
		i.RoutingKeys = svc.RoutingKeys

		i.ServiceEndpoint, err = svc.ServiceEndpoint.URI()
		require.NoError(t, err)
	}

	return i
}

func newServiceBlock() *diddoc.Service {
	var (
		sp                   commonmodel.Endpoint
		didCommV1RoutingKeys []string
	)

	sp = commonmodel.NewDIDCommV1Endpoint("http://test.com")
	didCommV1RoutingKeys = []string{uuid.New().String()}

	svc := &diddoc.Service{
		ID:              uuid.New().String(),
		Type:            didCommServiceType,
		RecipientKeys:   []string{uuid.New().String()},
		ServiceEndpoint: sp,
	}

	svc.Accept = []string{transport.MediaTypeRFC0019EncryptedEnvelope}
	svc.RoutingKeys = didCommV1RoutingKeys

	return svc
}

func connRecorder(t *testing.T, p provider) *connection.Recorder {
	s, err := connection.NewRecorder(p)
	require.NoError(t, err)

	return s
}

func getEpochTime() int64 {
	return time.Now().Unix()
}
