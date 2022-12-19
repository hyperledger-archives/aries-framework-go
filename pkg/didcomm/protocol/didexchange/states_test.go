/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	commonmodel "github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockdispatcher "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/dispatcher"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/store/connection"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
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
	require.False(t, comp.CanTransitionTo(&abandoned{}))
	require.False(t, comp.CanTransitionTo(comp))
}

func TestAbandonedState(t *testing.T) {
	ab := &abandoned{}
	require.Equal(t, StateIDAbandoned, ab.Name())
	require.False(t, ab.CanTransitionTo(&null{}))
	require.False(t, ab.CanTransitionTo(&invited{}))
	require.False(t, ab.CanTransitionTo(&requested{}))
	require.False(t, ab.CanTransitionTo(&responded{}))
	require.False(t, ab.CanTransitionTo(&completed{}))
	connRec, _, _, err := ab.ExecuteInbound(&stateMachineMsg{}, "", &context{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not implemented")
	require.Nil(t, connRec)
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
	t.Run("abandoned", func(t *testing.T) {
		expected := &abandoned{}
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
	t.Run("followup to 'requested' on inbound oobinvitations", func(t *testing.T) {
		connRec, followup, action, err := (&invited{}).ExecuteInbound(
			&stateMachineMsg{
				DIDCommMsg: service.NewDIDCommMsgMap(&OOBInvitation{Type: oobMsgType}),
				connRecord: &connection.Record{},
			},
			"",
			&context{},
		)
		require.NoError(t, err)
		require.Equal(t, &requested{}, followup)
		require.NotNil(t, connRec)
		require.NotNil(t, action)
	})
}

//nolint:gocognit,gocyclo
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
		transport.MediaTypeDIDCommV2Profile,
		transport.MediaTypeRFC0019EncryptedEnvelope,
		transport.MediaTypeProfileDIDCommAIP1,
	}

	for _, mtp := range mtps {
		var didServiceType string

		switch mtp {
		case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
			didServiceType = vdrapi.DIDCommV2ServiceType
		default:
			didServiceType = vdrapi.DIDCommServiceType
		}

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
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					msg, e := service.ParseDIDCommMsgMap(invitationPayloadBytes)
					require.NoError(t, e)
					thid, e := msg.ThreadID()
					require.NoError(t, e)
					connRec, _, _, e := (&requested{}).ExecuteInbound(&stateMachineMsg{
						DIDCommMsg: msg,
						connRecord: &connection.Record{},
					}, thid, tc.ctx)
					require.NoError(t, e)
					require.NotNil(t, connRec.MyDID)
				})
			}
		})
		t.Run("handle inbound oob invitations", func(t *testing.T) {
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					connRec, followup, action, e := (&requested{}).ExecuteInbound(&stateMachineMsg{
						DIDCommMsg: service.NewDIDCommMsgMap(&OOBInvitation{
							ID:         uuid.New().String(),
							Type:       oobMsgType,
							ThreadID:   uuid.New().String(),
							TheirLabel: "test",
							Target: &diddoc.Service{
								ID:              uuid.New().String(),
								Type:            didServiceType,
								Priority:        0,
								RecipientKeys:   []string{"key"},
								ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("http://test.com"),
							},
						}),
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.NoError(t, e)
					require.NotEmpty(t, connRec.MyDID)
					require.Equal(t, &noOp{}, followup)
					require.NotNil(t, action)
				})
			}
		})
		t.Run("handle inbound oob invitations", func(t *testing.T) {
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					connRec, followup, action, e := (&requested{}).ExecuteInbound(&stateMachineMsg{
						DIDCommMsg: service.NewDIDCommMsgMap(&OOBInvitation{
							ID:         uuid.New().String(),
							Type:       oobMsgType,
							ThreadID:   uuid.New().String(),
							TheirLabel: "test",
							Target: &diddoc.Service{
								ID:              uuid.New().String(),
								Type:            didServiceType,
								Priority:        0,
								RecipientKeys:   []string{"key"},
								ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("http://test.com"),
							},
						}),
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.NoError(t, e)
					require.NotEmpty(t, connRec.MyDID)
					require.Equal(t, &noOp{}, followup)
					require.NotNil(t, action)
				})
			}
		})
		t.Run("handle inbound oob invitations with label", func(t *testing.T) {
			expected := "my test label"
			dispatched := false
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					tc.ctx.outboundDispatcher = &mockdispatcher.MockOutbound{
						ValidateSend: func(msg interface{}, _ string, _ *service.Destination) error {
							dispatched = true
							result, ok := msg.(*Request)
							require.True(t, ok)
							require.Equal(t, expected, result.Label)
							return nil
						},
					}

					_, encKey := newSigningAndEncryptionDIDKeys(t, tc.ctx)

					inv := newOOBInvite(tc.ctx.mediaTypeProfiles, newServiceBlock([]string{encKey}, []string{encKey},
						didServiceType))
					inv.MyLabel = expected
					_, _, action, e := (&requested{}).ExecuteInbound(&stateMachineMsg{
						DIDCommMsg: service.NewDIDCommMsgMap(inv),
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.NoError(t, e)
					require.NotNil(t, action)
					err = action()
					require.NoError(t, err)
					require.True(t, dispatched)
				})
			}
		})
		t.Run("handle inbound oob invitations - register recipient keys in router", func(t *testing.T) {
			registered := false
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					_, expected := newSigningAndEncryptionDIDKeys(t, tc.ctx)
					_, encKey := newSigningAndEncryptionDIDKeys(t, tc.ctx)

					doc := createDIDDoc(t, tc.ctx)

					if didServiceType == vdrapi.DIDCommV2ServiceType {
						expected = doc.KeyAgreement[0].VerificationMethod.ID

						doc.Service = []diddoc.Service{{
							Type: didServiceType,
							ServiceEndpoint: commonmodel.NewDIDCommV2Endpoint([]commonmodel.DIDCommV2Endpoint{
								{URI: "http://test.com", Accept: []string{"didcomm/v2"}},
							}),
							RecipientKeys: []string{expected},
						}}
					} else {
						doc.Service = []diddoc.Service{{
							Type:            didServiceType,
							ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("http://test.com"),
							RecipientKeys:   []string{expected},
						}}
					}

					tc.ctx.vdRegistry = &mockvdr.MockVDRegistry{
						CreateValue: doc,
					}

					tc.ctx.routeSvc = &mockroute.MockMediatorSvc{
						Connections:    []string{"xyz"},
						RoutingKeys:    []string{expected},
						RouterEndpoint: "http://blah.com",
						AddKeyFunc: func(result string) error {
							require.Equal(t, expected, result)
							registered = true
							return nil
						},
					}
					_, _, _, err = (&requested{}).ExecuteInbound(&stateMachineMsg{
						options: &options{routerConnections: []string{"xyz"}},
						DIDCommMsg: service.NewDIDCommMsgMap(newOOBInvite(
							tc.ctx.mediaTypeProfiles,
							newServiceBlock([]string{encKey}, []string{encKey}, didServiceType))),
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.NoError(t, err)
					require.True(t, registered)
				})
			}
		})
		t.Run("handle inbound oob invitations - use routing info to create my did", func(t *testing.T) {
			expected := mediator.NewConfig("http://test.com", []string{"my-test-key"})
			created := false
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					_, encKey := newSigningAndEncryptionDIDKeys(t, tc.ctx)

					tc.ctx.routeSvc = &mockroute.MockMediatorSvc{
						Connections:    []string{"xyz"},
						RouterEndpoint: expected.Endpoint(),
						RoutingKeys:    expected.Keys(),
					}

					docResolution := createDIDDoc(t, tc.ctx)
					tc.ctx.vdRegistry = &mockvdr.MockVDRegistry{
						CreateFunc: func(_ string, didDoc *diddoc.Doc,
							options ...vdrapi.DIDMethodOption) (*diddoc.DocResolution, error) {
							created = true

							uri, e := didDoc.Service[0].ServiceEndpoint.URI()
							require.NoError(t, e)
							require.Equal(t, expected.Endpoint(), uri)
							return &diddoc.DocResolution{DIDDocument: docResolution}, nil
						},
						ResolveValue: docResolution,
					}

					oobInvite := newOOBInvite(tc.ctx.mediaTypeProfiles, newServiceBlock(
						[]string{encKey}, []string{encKey}, didServiceType))
					_, _, _, err = (&requested{}).ExecuteInbound(&stateMachineMsg{
						options:    &options{routerConnections: []string{"xyz"}},
						DIDCommMsg: service.NewDIDCommMsgMap(oobInvite),
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.NoError(t, err)
					require.True(t, created)

					// try with target as string
					oobInvite.Target = docResolution.ID
					_, _, _, err = (&requested{}).ExecuteInbound(&stateMachineMsg{
						options:    &options{routerConnections: []string{"xyz"}},
						DIDCommMsg: service.NewDIDCommMsgMap(oobInvite),
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.NoError(t, err)
					require.True(t, created)
				})
			}
		})
		t.Run("handling invitations fails if my diddoc does not have a valid didcomm service", func(t *testing.T) {
			msg, e := service.ParseDIDCommMsgMap(invitationPayloadBytes)
			require.NoError(t, e)
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					myDoc := createDIDDoc(t, tc.ctx)
					myDoc.Service = []diddoc.Service{{
						ID:              uuid.New().String(),
						Type:            "invalid",
						Priority:        0,
						RecipientKeys:   nil,
						ServiceEndpoint: commonmodel.NewDIDCommV2Endpoint([]commonmodel.DIDCommV2Endpoint{{}}),
					}}
					tc.ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: myDoc}
					_, _, _, err = (&requested{}).ExecuteInbound(&stateMachineMsg{
						DIDCommMsg: msg,
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.Error(t, err)
				})
			}
		})
		t.Run("handling OOB invitations fails if my diddoc does not have a valid didcomm service", func(t *testing.T) {
			tests := []struct {
				name string
				ctx  *context
			}{
				{
					name: "using context with ED25519 main VM and X25519 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
				},
				{
					name: "using context with P-256 main VM and P-256 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
				},
				{
					name: "using context with P-384 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
				},
				{
					name: "using context with P-521 main VM and P-521 keyAgreement",
					ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
				},
				{
					name: "using context with ED25519 main VM and P-384 keyAgreement",
					ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
				},
			}

			for _, tt := range tests {
				tc := tt
				t.Run(tc.name, func(t *testing.T) {
					myDoc := createDIDDoc(t, tc.ctx)
					myDoc.Service = []diddoc.Service{{
						ID:              uuid.New().String(),
						Type:            "invalid",
						Priority:        0,
						RecipientKeys:   nil,
						ServiceEndpoint: commonmodel.NewDIDCommV2Endpoint([]commonmodel.DIDCommV2Endpoint{{}}),
					}}
					tc.ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: myDoc}
					_, _, _, err = (&requested{}).ExecuteInbound(&stateMachineMsg{
						DIDCommMsg: service.NewDIDCommMsgMap(&OOBInvitation{
							ID:         uuid.New().String(),
							Type:       oobMsgType,
							ThreadID:   uuid.New().String(),
							TheirLabel: "test",
							Target: &diddoc.Service{
								ID:              uuid.New().String(),
								Type:            didServiceType,
								Priority:        0,
								RecipientKeys:   []string{"key"},
								ServiceEndpoint: commonmodel.NewDIDCommV1Endpoint("http://test.com"),
							},
						}),
						connRecord: &connection.Record{},
					}, "", tc.ctx)
					require.EqualError(t, err, "failed to handle inbound oob invitation : getting recipient key:"+
						" recipientKeyAsDIDKey: invalid DID Doc service type: 'invalid'")
				})
			}
		})
		t.Run("inbound oob request error", func(t *testing.T) {
			_, _, _, err = (&requested{}).ExecuteInbound(&stateMachineMsg{
				DIDCommMsg: service.DIDCommMsgMap{
					"@type": oobMsgType,
					"@id":   map[int]int{},
				},
				connRecord: &connection.Record{},
			}, "", &context{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to decode oob invitation: 1 error(s) decoding")
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
	mtps := []string{transport.MediaTypeDIDCommV2Profile, transport.MediaTypeRFC0019EncryptedEnvelope}

	for _, mtp := range mtps {
		prov := getProvider(t)
		tests := []struct {
			name string
			ctx  *context
		}{
			{
				name: fmt.Sprintf("using context with ED25519 main VM and X25519 keyAgreement with profile %s", mtp),
				ctx:  getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp),
			},
			{
				name: fmt.Sprintf("using context with P-256 main VM and P-256 keyAgreement with profile %s", mtp),
				ctx:  getContext(t, &prov, kms.ECDSAP256TypeIEEEP1363, kms.NISTP256ECDHKWType, mtp),
			},
			{
				name: fmt.Sprintf("using context with P-384 main VM and P-384 keyAgreement with profile %s", mtp),
				ctx:  getContext(t, &prov, kms.ECDSAP384TypeIEEEP1363, kms.NISTP384ECDHKWType, mtp),
			},
			{
				name: fmt.Sprintf("using context with P-521 main VM and P-521 keyAgreement with profile %s", mtp),
				ctx:  getContext(t, &prov, kms.ECDSAP521TypeIEEEP1363, kms.NISTP521ECDHKWType, mtp),
			},
			{
				name: fmt.Sprintf("using context with ED25519 main VM and P-384 keyAgreement with profile %s", mtp),
				ctx:  getContext(t, &prov, kms.ED25519Type, kms.NISTP384ECDHKWType, mtp),
			},
		}

		for _, tt := range tests {
			tc := tt
			t.Run(tc.name, func(t *testing.T) {
				request, err := createRequest(t, tc.ctx, false, mtp)
				require.NoError(t, err)
				requestPayloadBytes, err := json.Marshal(request)
				require.NoError(t, err)
				response, err := createResponse(request, tc.ctx)
				require.NoErrorf(t, err, fmt.Sprintf("for %s", tc.name))
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
					}, "", tc.ctx)
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
					err = tc.ctx.connectionRecorder.SaveConnectionRecordWithMappings(connRec)
					require.NoError(t, err)
					connRec, followup, _, e := (&responded{}).ExecuteInbound(
						&stateMachineMsg{
							DIDCommMsg: bytesToDIDCommMsg(t, responsePayloadBytes),
							connRecord: connRec,
						}, "", tc.ctx)
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
					ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)
					myDoc := createDIDDoc(t, ctx)
					myDoc.Service = []diddoc.Service{{
						ID:              uuid.New().String(),
						Type:            "invalid",
						Priority:        0,
						RecipientKeys:   nil,
						ServiceEndpoint: commonmodel.NewDIDCommV2Endpoint([]commonmodel.DIDCommV2Endpoint{{}}),
					}}
					ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: myDoc}
					_, _, _, err := (&responded{}).ExecuteInbound(&stateMachineMsg{
						DIDCommMsg: bytesToDIDCommMsg(t, requestPayloadBytes),
						connRecord: &connection.Record{},
					}, "", ctx)
					require.Error(t, err)
				})
			})
		}
	}
}

func TestAbandonedState_Execute(t *testing.T) {
	t.Run("execute abandon state", func(t *testing.T) {
		connRec, _, _, err := (&abandoned{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: service.NewDIDCommMsgMap(Response{Type: ResponseMsgType}),
		}, "", &context{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not implemented")
		require.Nil(t, connRec)
	})
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
	pubKey, encKey := newSigningAndEncryptionDIDKeys(t, ctx)
	connRec, err := connection.NewRecorder(&prov)

	require.NoError(t, err)
	require.NotNil(t, connRec)

	ctx.connectionRecorder = connRec

	newDIDDoc := createDIDDocWithKey(pubKey, encKey, transport.MediaTypeRFC0019EncryptedEnvelope)

	invitation, err := createMockInvitation(pubKey, ctx)
	require.NoError(t, err)

	didKey, err := ctx.getVerKey(invitation.ID)
	require.NoError(t, err)

	docAttach, err := ctx.didDocAttachment(newDIDDoc, didKey)
	require.NoError(t, err)

	response := &Response{
		Type:      ResponseMsgType,
		ID:        randomString(),
		DocAttach: docAttach,
		DID:       newDIDDoc.ID,
		Thread: &decorator.Thread{
			ID: "test",
		},
	}
	responsePayloadBytes, err := json.Marshal(response)
	require.NoError(t, err)

	t.Run("no followup for inbound responses", func(t *testing.T) {
		connRec := &connection.Record{
			State:         (&responded{}).Name(),
			ThreadID:      response.Thread.ID,
			ConnectionID:  "123",
			MyDID:         "did:peer:123456789abcdefghi#inbox",
			Namespace:     myNSPrefix,
			InvitationID:  invitation.ID,
			RecipientKeys: []string{pubKey},
		}
		err = ctx.connectionRecorder.SaveConnectionRecordWithMappings(connRec)
		require.NoError(t, err)
		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: mockdiddoc.GetMockDIDDoc(t, false)}
		require.NoError(t, err)
		_, followup, _, e := (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: bytesToDIDCommMsg(t, responsePayloadBytes),
			connRecord: connRec,
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
	})
	t.Run("no followup for inbound acks", func(t *testing.T) {
		connRec := &connection.Record{
			State:         (&responded{}).Name(),
			ThreadID:      response.Thread.ID,
			ConnectionID:  "123",
			Namespace:     findNamespace(AckMsgType),
			RecipientKeys: []string{pubKey},
		}
		err = ctx.connectionRecorder.SaveConnectionRecordWithMappings(connRec)
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
	t.Run("no followup for inbound complete", func(t *testing.T) {
		connRec := &connection.Record{
			State:         (&responded{}).Name(),
			ThreadID:      response.Thread.ID,
			ConnectionID:  "123",
			Namespace:     findNamespace(AckMsgType),
			RecipientKeys: []string{pubKey},
		}
		err = ctx.connectionRecorder.SaveConnectionRecordWithMappings(connRec)
		require.NoError(t, err)
		complete := &Complete{
			Type: CompleteMsgType,
			ID:   randomString(),
			Thread: &decorator.Thread{
				ID: response.Thread.ID,
			},
		}
		// without connection record
		payloadBytes, e := json.Marshal(complete)
		require.NoError(t, e)
		_, followup, _, e := (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: bytesToDIDCommMsg(t, payloadBytes),
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
		// with connection record
		connRec.TheirDID = "did:abc:test123"
		_, followup, _, e = (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: bytesToDIDCommMsg(t, payloadBytes),
			connRecord: connRec,
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
		// with connection record with sov interop fix
		connRec.TheirDID = "test123"
		ctx.doACAPyInterop = true
		_, followup, _, e = (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: bytesToDIDCommMsg(t, payloadBytes),
			connRecord: connRec,
		}, "", ctx)
		require.NoError(t, e)
		require.IsType(t, &noOp{}, followup)
		ctx.doACAPyInterop = false
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
	t.Run("inbound completes unmarshalling error", func(t *testing.T) {
		_, followup, _, err := (&completed{}).ExecuteInbound(&stateMachineMsg{
			DIDCommMsg: service.DIDCommMsgMap{"@id": map[int]int{}, "@type": CompleteMsgType},
		}, "", &context{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "JSON unmarshalling of complete")
		require.Nil(t, followup)
	})
	t.Run("execute inbound handle inbound response  error", func(t *testing.T) {
		response.DID = ""
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
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
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
	t.Run("successful response to invitation with public did using P-384 key type", func(t *testing.T) {
		prov := getProvider(t)
		ctx := &context{
			kms:               prov.CustomKMS,
			keyType:           kms.ECDSAP384TypeIEEEP1363,
			keyAgreementType:  kms.NISTP384ECDHKWType,
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
	t.Run("unsuccessful new request from invitation with P-384 key as KW", func(t *testing.T) {
		prov := protocol.MockProvider{}
		customKMS := newKMS(t, mem.NewProvider())

		ctx := &context{
			kms:                customKMS,
			outboundDispatcher: prov.OutboundDispatcher(),
			routeSvc:           &mockroute.MockMediatorSvc{},
			vdRegistry:         &mockvdr.MockVDRegistry{CreateErr: fmt.Errorf("create DID error")},
			keyType:            kms.ED25519Type,
			keyAgreementType:   kms.NISTP384ECDHKWType,
			mediaTypeProfiles:  []string{transport.MediaTypeRFC0019EncryptedEnvelope},
		}
		_, connRec, err := ctx.handleInboundInvitation(invitation, invitation.ID, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create DID error")
		require.Nil(t, connRec)
	})
	t.Run("unsuccessful new request from invitation (creating did doc attachment for request)", func(t *testing.T) {
		prov := getProvider(t)
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)

		ctx.doACAPyInterop = true
		ctx.crypto = &mockcrypto.Crypto{
			SignErr: fmt.Errorf("sign error"),
		}

		_, _, err := ctx.handleInboundInvitation(invitation, invitation.ID, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "creating did doc attachment for request")
	})
}

func TestNewResponseFromRequest(t *testing.T) {
	prov := getProvider(t)
	store := mockstorage.NewMockStoreProvider()
	k := newKMS(t, store)

	t.Run("successful new response from request", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		request, err := createRequest(t, ctx, false, ctx.mediaTypeProfiles[0])
		require.NoError(t, err)
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.NoError(t, err)
		require.NotNil(t, connRec.MyDID)
		require.NotNil(t, connRec.TheirDID)
	})

	t.Run("unsuccessful new response from request due to resolve DID error", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		request.DID = ""

		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolve did doc from exchange request")
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
			DID:       didDoc.ID,
			DocAttach: signedDocAttach(t, didDoc),
		}
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "create DID error")
		require.Nil(t, connRec)
	})

	t.Run("unsuccessful new response from request due to get did doc error", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.connectionStore = &mockConnectionStore{saveDIDFromDocErr: fmt.Errorf("save did error")}

		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)
		_, connRec, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get response did doc and connection")
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

		request, err := createRequest(t, ctx, true, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		_, connRecord, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})

		require.Error(t, err)
		require.Contains(t, err.Error(), "sign error")
		require.Nil(t, connRecord)
	})

	t.Run("unsuccessful new response from request due to resolve public did from request error", func(t *testing.T) {
		ctx := &context{vdRegistry: &mockvdr.MockVDRegistry{ResolveErr: errors.New("resolver error")}}
		request := &Request{DID: "did:sidetree:abc"}
		_, _, err := ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "resolver error")
	})

	t.Run("unsuccessful new response from request due to invalid did for creating destination", func(t *testing.T) {
		mockDoc := newPeerDID(t, k)
		mockDoc.Service = nil

		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)

		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		request.DID = mockDoc.ID
		request.DocAttach = unsignedDocAttach(t, mockDoc)

		_, _, err = ctx.handleInboundRequest(request, &options{}, &connection.Record{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing DID doc service")
	})
}

func TestPrepareResponse(t *testing.T) {
	prov := getProvider(t)

	t.Run("successful new response from request", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		_, err = ctx.prepareResponse(request, mockdiddoc.GetMockDIDDoc(t, false))
		require.NoError(t, err)
	})

	t.Run("successful new response from request, in interop mode", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.doACAPyInterop = true

		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		_, err = ctx.prepareResponse(request, mockdiddoc.GetMockDIDDoc(t, false))
		require.NoError(t, err)
	})

	t.Run("wraps error from connection store", func(t *testing.T) {
		expected := errors.New("test")
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.doACAPyInterop = true

		pr := testProvider()
		pr.StoreProvider = &mockstorage.MockStoreProvider{
			Store: &mockstorage.MockStore{
				Store:  make(map[string]mockstorage.DBEntry),
				ErrGet: expected,
			},
		}

		ctx.connectionRecorder = connRecorder(t, pr)

		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		_, err = ctx.prepareResponse(request, mockdiddoc.GetMockDIDDoc(t, false))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("failed fetch of doc signing key", func(t *testing.T) {
		expected := errors.New("test")
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.doACAPyInterop = true

		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		ctx.kms = &mockkms.KeyManager{GetKeyErr: expected}

		_, err = ctx.prepareResponse(request, mockdiddoc.GetMockDIDDoc(t, false))
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})

	t.Run("failed doc signing", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.doACAPyInterop = true

		request, err := createRequest(t, ctx, false, transport.MediaTypeRFC0019EncryptedEnvelope)
		require.NoError(t, err)

		// fails to do ed25519 sign with wrong type of key
		mockKey, err := mockkms.CreateMockAESGCMKeyHandle()
		require.NoError(t, err)

		ctx.kms = &mockkms.KeyManager{GetKeyValue: mockKey}

		_, err = ctx.prepareResponse(request, mockdiddoc.GetMockDIDDoc(t, false))
		require.Error(t, err)
	})
}

func TestContext_DIDDocAttachment(t *testing.T) {
	prov := getProvider(t)

	t.Run("successful new did doc attachment without signing", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)

		doc := mockdiddoc.GetMockDIDDoc(t, false)

		att, err := ctx.didDocAttachment(doc, "")
		require.NoError(t, err)

		attData, err := att.Data.Fetch()
		require.NoError(t, err)

		checkDoc, err := diddoc.ParseDocument(attData)
		require.NoError(t, err)
		require.NotNil(t, checkDoc)

		require.Equal(t, checkDoc.ID, doc.ID)
	})

	t.Run("successful new did doc attachment with signing", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.doACAPyInterop = true

		doc := mockdiddoc.GetMockDIDDoc(t, false)

		_, pub, err := ctx.kms.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		didKey, _ := fingerprint.CreateDIDKey(pub)

		att, err := ctx.didDocAttachment(doc, didKey)
		require.NoError(t, err)

		attData, err := att.Data.Fetch()
		require.NoError(t, err)

		checkDoc, err := diddoc.ParseDocument(attData)
		require.NoError(t, err)
		require.NotNil(t, checkDoc)

		require.Equal(t, checkDoc.ID, doc.ID)
	})

	t.Run("fail to create did doc attachment, invalid key", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.doACAPyInterop = true

		doc := mockdiddoc.GetMockDIDDoc(t, false)

		_, err := ctx.didDocAttachment(doc, "did:key:not a did key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to extract pubKeyBytes")
	})

	t.Run("fail to create did doc attachment, can't create KID", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		ctx.doACAPyInterop = true

		doc := mockdiddoc.GetMockDIDDoc(t, false)

		didKey, _ := fingerprint.CreateDIDKey([]byte{})

		_, err := ctx.didDocAttachment(doc, didKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to generate KID from public key")
	})
}

func TestResolvePublicKey(t *testing.T) {
	prov := getProvider(t)

	t.Run("resolve key from did:key", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)

		keyBytes := []byte("12345678123456781234567812345678")
		didKey, _ := fingerprint.CreateDIDKey(keyBytes)

		pub, err := ctx.resolvePublicKey(didKey)
		require.NoError(t, err)
		require.EqualValues(t, keyBytes, pub)
	})

	t.Run("resolve key reference from doc in vdr", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		doc := mockdiddoc.GetMockDIDDoc(t, false)
		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: doc}

		vm := doc.VerificationMethod[0]

		pub, err := ctx.resolvePublicKey(vm.ID)
		require.NoError(t, err)
		require.EqualValues(t, vm.Value, pub)
	})

	t.Run("fail to resolve public key from unknown kid", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)

		_, err := ctx.resolvePublicKey("something something")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve public key value from kid")
	})

	t.Run("fail to resolve public key from invalid did:key", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)

		_, err := ctx.resolvePublicKey("did:key:not a did key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to extract pubKeyBytes")
	})

	t.Run("fail to resolve doc for key reference", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		doc := mockdiddoc.GetMockDIDDoc(t, false)

		vm := doc.VerificationMethod[0]

		_, err := ctx.resolvePublicKey(vm.ID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve public did")
	})

	t.Run("fail to find key in resolved doc", func(t *testing.T) {
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		doc := mockdiddoc.GetMockDIDDoc(t, false)
		ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: doc}

		kid := doc.VerificationMethod[0].ID

		doc.VerificationMethod[0].ID = "wrong-key-id"

		_, err := ctx.resolvePublicKey(kid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to lookup public key")
	})
}

func TestResolveDIDDocFromMessage(t *testing.T) {
	prov := getProvider(t)
	mtps := []string{transport.MediaTypeDIDCommV2Profile, transport.MediaTypeRFC0019EncryptedEnvelope}

	for _, mtp := range mtps {
		t.Run(fmt.Sprintf("success with media type profile: %s", mtp), func(t *testing.T) {
			ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)
			docIn := mockdiddoc.GetMockDIDDoc(t, false)

			att, err := ctx.didDocAttachment(docIn, "")
			require.NoError(t, err)

			doc, err := ctx.resolveDidDocFromMessage(docIn.ID, att)
			require.NoError(t, err)

			require.Equal(t, docIn.ID, doc.ID)
		})

		t.Run(fmt.Sprintf("success - public resolution with media type profile: %s", mtp), func(t *testing.T) {
			ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)
			docIn := mockdiddoc.GetMockDIDDoc(t, false)
			docIn.ID = "did:remote:abc"

			ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveValue: docIn}

			doc, err := ctx.resolveDidDocFromMessage(docIn.ID, nil)
			require.NoError(t, err)

			require.Equal(t, docIn.ID, doc.ID)
		})

		t.Run(fmt.Sprintf("failure - can't do public resolution with media type profile: %s", mtp),
			func(t *testing.T) {
				ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)
				docIn := mockdiddoc.GetMockDIDDoc(t, false)
				docIn.ID = "did:remote:abc"

				ctx.vdRegistry = &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf("resolve error")}

				_, err := ctx.resolveDidDocFromMessage(docIn.ID, nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to resolve public did")
			})

		t.Run(fmt.Sprintf("failure - can't parse did with media type profile: %s", mtp), func(t *testing.T) {
			ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)
			_, err := ctx.resolveDidDocFromMessage("blah blah", nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to parse did")
		})

		t.Run(fmt.Sprintf("failure - missing attachment for private did with media type profile: %s", mtp),
			func(t *testing.T) {
				ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)
				_, err := ctx.resolveDidDocFromMessage("did:peer:abcdefg", nil)
				require.Error(t, err)
				require.Contains(t, err.Error(), "missing did_doc~attach")
			})

		t.Run(fmt.Sprintf("failure - bad base64 data in attachment with media type profile: %s", mtp),
			func(t *testing.T) {
				ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)

				att := decorator.Attachment{Data: decorator.AttachmentData{Base64: "!@#$%^&*"}}

				_, err := ctx.resolveDidDocFromMessage("did:peer:abcdefg", &att)
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to parse base64 attachment data")
			})

		t.Run(fmt.Sprintf("failure - attachment contains encoded broken document with media type profile: %s",
			mtp), func(t *testing.T) {
			ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)

			att := decorator.Attachment{
				Data: decorator.AttachmentData{
					Base64: base64.StdEncoding.EncodeToString([]byte("abcdefg")),
				},
			}

			_, err := ctx.resolveDidDocFromMessage("did:peer:abcdefg", &att)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to parse did document")
		})

		t.Run(fmt.Sprintf("success - interop mode with media type profile: %s", mtp), func(t *testing.T) {
			ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)

			docIn := mockdiddoc.GetMockDIDDoc(t, false)
			docIn.ID = "did:sov:abcdefg"

			att, err := ctx.didDocAttachment(docIn, "")
			require.NoError(t, err)

			ctx.doACAPyInterop = true

			doc, err := ctx.resolveDidDocFromMessage(docIn.ID, att)
			require.NoError(t, err)

			require.Equal(t, docIn.ID, doc.ID)
		})

		t.Run(fmt.Sprintf("failure - can't store document locally with media type profile: %s", mtp),
			func(t *testing.T) {
				ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, mtp)

				ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateErr: fmt.Errorf("create error")}

				docIn := mockdiddoc.GetMockDIDDoc(t, false)

				att, err := ctx.didDocAttachment(docIn, "")
				require.NoError(t, err)

				_, err = ctx.resolveDidDocFromMessage(docIn.ID, att)
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to store provided did document")
			})
	}
}

func TestHandleInboundResponse(t *testing.T) {
	prov := getProvider(t)
	ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
	_, encKey := newSigningAndEncryptionDIDKeys(t, ctx)

	_, err := createMockInvitation(encKey, ctx)
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
	ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)

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
		// TODO fix hardcode base58 https://github.com/hyperledger/aries-framework-go/issues/1207
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
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
		doc, err := ctx.vdRegistry.Create(testMethod, nil)
		require.NoError(t, err)
		pubkey, ok := diddoc.LookupPublicKey(doc.DIDDocument.VerificationMethod[0].ID, doc.DIDDocument)
		require.True(t, ok)
		require.NotNil(t, pubkey)
	})
	t.Run("failed to get public key", func(t *testing.T) {
		prov := protocol.MockProvider{CustomKMS: k}
		ctx := getContext(t, &prov, kms.ED25519Type, kms.X25519ECDHKWType, transport.MediaTypeRFC0019EncryptedEnvelope)
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
		didDoc, err := ctx.getMyDIDDoc("", nil, didCommV2ServiceType)
		require.NoError(t, err)
		require.NotNil(t, didDoc)
	})

	t.Run("successfully created peer did with didcomm V2 service bloc", func(t *testing.T) {
		connRec, err := connection.NewRecorder(&protocol.MockProvider{})
		require.NoError(t, err)
		didConnStore, err := didstore.NewConnectionStore(&protocol.MockProvider{})
		require.NoError(t, err)
		customKMS := newKMS(t, mockstorage.NewMockStoreProvider())
		ctx := context{
			kms:                customKMS,
			vdRegistry:         &mockvdr.MockVDRegistry{CreateValue: mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "bob")},
			connectionRecorder: connRec,
			connectionStore:    didConnStore,
			routeSvc:           &mockroute.MockMediatorSvc{},
			keyType:            kms.ED25519Type,
			keyAgreementType:   kms.X25519ECDHKWType,
		}
		didDoc, err := ctx.getMyDIDDoc("", []string{"did:peer:bob"}, didCommV2ServiceType)
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
			kms:                customKMS,
			vdRegistry:         &mockvdr.MockVDRegistry{CreateValue: mockdiddoc.GetMockDIDDoc(t, false)},
			connectionRecorder: connRec,
			routeSvc: &mockroute.MockMediatorSvc{
				Connections: []string{"xyz"},
				AddKeyErr:   errors.New("router add key error"),
			},
			keyType:          kms.ED25519Type,
			keyAgreementType: kms.X25519ECDHKWType,
		}
		didDoc, err := ctx.getMyDIDDoc("", []string{"xyz"}, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did doc - add key to the router")
		require.Nil(t, didDoc)
	})

	t.Run("error - invalid service type", func(t *testing.T) {
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
		didDoc, err := ctx.getMyDIDDoc("", nil, "")
		require.Error(t, err)
		require.Nil(t, didDoc)
		require.Contains(t, err.Error(), "getMyDIDDoc: invalid DID Doc service type: ''")
	})
}

const sovDoc = `{
  "@context": "https://www.w3.org/2019/did/v1",
  "id": "did:sov:17hRTxZFuRqqwFPxXnnuLj",
  "service": [
    {
      "type": "endpoint",
      "serviceEndpoint": "http://172.17.0.1:9031"
    }
  ],
  "authentication": [
    {
      "type": "Ed25519SignatureAuthentication2018",
      "publicKey": [
        "did:sov:17hRTxZFuRqqwFPxXnnuLj#key-1"
      ]
    }
  ],
  "publicKey": [
    {
      "id": "did:sov:17hRTxZFuRqqwFPxXnnuLj#key-1",
      "type": "Ed25519VerificationKey2018",
      "publicKeyBase58": "14ehnBh9oevUhQUADCRk5dmMCk3cmLukZcKNCTxLGiic"
    }
  ]
}`

func TestGetServiceBlock(t *testing.T) {
	doc, err := diddoc.ParseDocument([]byte(sovDoc))
	require.NoError(t, err)

	v := &mockvdr.MockVDRegistry{ResolveValue: doc}

	t.Run("success: get service block from public sov did", func(t *testing.T) {
		ctx := &context{
			doACAPyInterop: true,
			vdRegistry:     v,
		}

		inv := newOOBInvite([]string{transport.MediaTypeRFC0019EncryptedEnvelope}, doc.ID)

		svc, err := ctx.getServiceBlock(inv)
		require.NoError(t, err)
		require.Len(t, svc.RecipientKeys, 1)
	})

	t.Run("failure: get service block from public sov did, not in interop mode", func(t *testing.T) {
		ctx := &context{
			vdRegistry: v,
		}

		inv := newOOBInvite([]string{transport.MediaTypeRFC0019EncryptedEnvelope}, doc.ID)

		svc, err := ctx.getServiceBlock(inv)
		require.Error(t, err)
		require.Nil(t, svc)
		require.Contains(t, err.Error(), "no valid service block found")
	})

	t.Run("failure: get service block from public sov did, doc does not have endpoint service", func(t *testing.T) {
		doc2, err := diddoc.ParseDocument([]byte(sovDoc))
		require.NoError(t, err)

		doc2.Service = nil

		ctx := &context{
			vdRegistry:     &mockvdr.MockVDRegistry{ResolveValue: doc2},
			doACAPyInterop: true,
		}

		inv := newOOBInvite([]string{transport.MediaTypeRFC0019EncryptedEnvelope}, doc.ID)

		svc, err := ctx.getServiceBlock(inv)
		require.Error(t, err)
		require.Nil(t, svc)
		require.Contains(t, err.Error(), "failed to get interop doc service")
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

	_, encKey := newSigningAndEncryptionDIDKeys(t, ctx)

	t.Run("returns verkey from explicit oob invitation", func(t *testing.T) {
		expected := newServiceBlock([]string{encKey}, []string{encKey}, didCommServiceType)
		invitation := newOOBInvite(expected.Accept, expected)
		ctx.connectionRecorder = connRecorder(t, testProvider())

		err := ctx.connectionRecorder.SaveInvitation(invitation.ThreadID, invitation)
		require.NoError(t, err)

		result, err := ctx.getVerKey(invitation.ThreadID)
		require.NoError(t, err)
		require.Equal(t, expected.RecipientKeys[0], result)

		expected = newServiceBlock([]string{encKey}, []string{encKey}, didCommV2ServiceType)
		accept, err := expected.ServiceEndpoint.Accept()
		require.NoError(t, err)
		invitation = newOOBInvite(accept, expected)
		ctx.connectionRecorder = connRecorder(t, testProvider())

		err = ctx.connectionRecorder.SaveInvitation(invitation.ThreadID, invitation)
		require.NoError(t, err)

		result, err = ctx.getVerKey(invitation.ThreadID)
		require.NoError(t, err)
		require.Equal(t, expected.RecipientKeys[0], result)
	})
	t.Run("returns verkey from implicit oob invitation", func(t *testing.T) {
		publicDID := createDIDDoc(t, ctx)
		invitation := newOOBInvite([]string{ctx.mediaTypeProfiles[0]}, publicDID.ID)
		ctx.connectionRecorder = connRecorder(t, testProvider())
		ctx.vdRegistry = &mockvdr.MockVDRegistry{
			ResolveValue: publicDID,
		}

		err := ctx.connectionRecorder.SaveInvitation(invitation.ThreadID, invitation)
		require.NoError(t, err)

		result, err := ctx.getVerKey(invitation.ThreadID)
		require.NoError(t, err)
		require.Equal(t, publicDID.Service[0].RecipientKeys[0], result)
	})

	t.Run("returns verkey from implicit (interop) oob invitation", func(t *testing.T) {
		publicDID, err := diddoc.ParseDocument([]byte(sovDoc))
		require.NoError(t, err)
		invitation := newOOBInvite([]string{transport.MediaTypeRFC0019EncryptedEnvelope}, publicDID.ID)
		ctx.connectionRecorder = connRecorder(t, testProvider())
		ctx.vdRegistry = &mockvdr.MockVDRegistry{
			ResolveValue: publicDID,
		}
		ctx.doACAPyInterop = true

		err = ctx.connectionRecorder.SaveInvitation(invitation.ThreadID, invitation)
		require.NoError(t, err)

		result, err := ctx.getVerKey(invitation.ThreadID)
		require.NoError(t, err)
		require.Equal(t, publicDID.Service[0].RecipientKeys[0], result)

		ctx.doACAPyInterop = false
	})

	t.Run("returns verkey from explicit didexchange invitation", func(t *testing.T) {
		expected := newServiceBlock([]string{encKey}, []string{encKey}, didCommServiceType)
		invitation := newDidExchangeInvite(t, "", expected)
		ctx.connectionRecorder = connRecorder(t, testProvider())

		err := ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
		require.NoError(t, err)

		result, err := ctx.getVerKey(invitation.ID)
		require.NoError(t, err)
		require.Equal(t, expected.RecipientKeys[0], result)

		expected = newServiceBlock([]string{encKey}, []string{encKey}, didCommV2ServiceType)
		invitation = newDidExchangeInvite(t, "", expected)
		ctx.connectionRecorder = connRecorder(t, testProvider())

		err = ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
		require.NoError(t, err)

		result, err = ctx.getVerKey(invitation.ID)
		require.NoError(t, err)
		require.Equal(t, expected.RecipientKeys[0], result)
	})

	t.Run("returns verkey from implicit didexchange invitation", func(t *testing.T) {
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

	t.Run("fails for oob invitation with no target", func(t *testing.T) {
		invalid := newOOBInvite(nil, nil)
		ctx.connectionRecorder = connRecorder(t, testProvider())

		err := ctx.connectionRecorder.SaveInvitation(invalid.ThreadID, invalid)
		require.NoError(t, err)

		_, err = ctx.getVerKey(invalid.ThreadID)
		require.Error(t, err)
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

		invitation := newOOBInvite([]string{transport.MediaTypeRFC0019EncryptedEnvelope},
			newServiceBlock([]string{encKey}, []string{encKey}, didCommServiceType))
		err := ctx.connectionRecorder.SaveInvitation(invitation.ID, invitation)
		require.NoError(t, err)

		invitation = newOOBInvite([]string{transport.MediaTypeDIDCommV2Profile},
			newServiceBlock([]string{encKey}, []string{encKey}, didCommV2ServiceType))
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
	t.Helper()

	verDIDKey, encDIDKey := newSigningAndEncryptionDIDKeys(t, ctx)

	return createDIDDocWithKey(verDIDKey, encDIDKey, ctx.mediaTypeProfiles[0])
}

func createDIDDocWithKey(verDIDKey, encDIDKey, mediaTypeProfile string) *diddoc.Doc {
	const (
		didFormat    = "did:%s:%s"
		didPKID      = "%s#keys-%d"
		didServiceID = "%s#endpoint-%d"
		method       = "test"
	)

	id := fmt.Sprintf(didFormat, method, verDIDKey[:16])
	pubKeyID := fmt.Sprintf(didPKID, id, 1)
	verPubKeyVM := diddoc.VerificationMethod{
		ID:         pubKeyID,
		Type:       "Ed25519VerificationKey2018",
		Controller: id,
		Value:      []byte(verDIDKey),
	}

	encPubKeyID := fmt.Sprintf(didPKID, id, 2)
	encKeyV := diddoc.Verification{
		VerificationMethod: diddoc.VerificationMethod{
			ID:         encPubKeyID,
			Type:       "X25519KeyAgreementKey2019",
			Controller: id,
			Value:      []byte(encDIDKey),
		},
		Relationship: diddoc.KeyAgreement,
	}

	var (
		didCommService string
		recKey         string
		sp             commonmodel.Endpoint
	)

	switch mediaTypeProfile {
	case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
		didCommService = vdrapi.DIDCommV2ServiceType
		recKey = verDIDKey
		sp = commonmodel.NewDIDCommV2Endpoint([]commonmodel.DIDCommV2Endpoint{
			{URI: "http://localhost:58416", Accept: []string{mediaTypeProfile}},
		})
	default:
		didCommService = vdrapi.DIDCommServiceType
		recKey = encPubKeyID
		sp = commonmodel.NewDIDCommV1Endpoint("http://localhost:58416")
	}

	services := []diddoc.Service{
		{
			ID:              fmt.Sprintf(didServiceID, id, 1),
			Type:            didCommService,
			ServiceEndpoint: sp,
			Priority:        0,
			RecipientKeys:   []string{recKey},
		},
	}

	switch mediaTypeProfile {
	case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile:
	default: // set DIDComm V1 Accept field.
		services[0].Accept = []string{mediaTypeProfile}
	}

	createdTime := time.Now()
	didDoc := &diddoc.Doc{
		Context:            []string{diddoc.ContextV1},
		ID:                 id,
		VerificationMethod: []diddoc.VerificationMethod{verPubKeyVM, encKeyV.VerificationMethod},
		KeyAgreement:       []diddoc.Verification{encKeyV},
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

func getContext(t *testing.T, prov *protocol.MockProvider, keyType, keyAgreementType kms.KeyType,
	mediaTypeProfile string) *context {
	t.Helper()

	ctx := &context{
		outboundDispatcher: prov.OutboundDispatcher(),
		crypto:             &tinkcrypto.Crypto{},
		routeSvc:           &mockroute.MockMediatorSvc{},
		kms:                prov.KMS(),
		keyType:            keyType,
		keyAgreementType:   keyAgreementType,
		mediaTypeProfiles:  []string{mediaTypeProfile},
	}

	pubKey, encKey := newSigningAndEncryptionDIDKeys(t, ctx)
	connRec, err := connection.NewRecorder(prov)
	require.NoError(t, err)

	didConnStore, err := didstore.NewConnectionStore(prov)
	require.NoError(t, err)

	ctx.vdRegistry = &mockvdr.MockVDRegistry{CreateValue: createDIDDocWithKey(pubKey, encKey, mediaTypeProfile)}
	ctx.connectionRecorder = connRec
	ctx.connectionStore = didConnStore

	return ctx
}

func createRequest(t *testing.T, ctx *context, signDoc bool, mediaTypeProfile string) (*Request, error) {
	t.Helper()

	pubKey, encKey := newSigningAndEncryptionDIDKeys(t, ctx)

	invitation, err := createMockInvitation(pubKey, ctx)
	if err != nil {
		return nil, err
	}

	newDidDoc := createDIDDocWithKey(pubKey, encKey, mediaTypeProfile)

	var att *decorator.Attachment
	if signDoc {
		att = signedDocAttach(t, newDidDoc)
	} else {
		att = unsignedDocAttach(t, newDidDoc)
	}

	// Prepare did-exchange inbound request
	request := &Request{
		Type:  RequestMsgType,
		ID:    randomString(),
		Label: "Bob",
		Thread: &decorator.Thread{
			PID: invitation.ID,
		},

		DID:       newDidDoc.ID,
		DocAttach: att,
	}

	return request, nil
}

func createResponse(request *Request, ctx *context) (*Response, error) {
	doc, err := ctx.vdRegistry.Create(testMethod, nil)
	if err != nil {
		return nil, err
	}

	didKey, err := ctx.getVerKey(request.Thread.PID)
	if err != nil {
		return nil, err
	}

	docAttach, err := ctx.didDocAttachment(doc.DIDDocument, didKey)
	if err != nil {
		return nil, err
	}

	response := &Response{
		Type: ResponseMsgType,
		ID:   randomString(),
		Thread: &decorator.Thread{
			ID: request.ID,
		},
		DocAttach: docAttach,
	}

	return response, nil
}

func createMockInvitation(pubKey string, ctx *context) (*Invitation, error) {
	invitation := &Invitation{
		Type:            InvitationMsgType,
		ID:              randomString(),
		Label:           "Bob",
		RecipientKeys:   []string{pubKey},
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

func newDidExchangeInvite(t *testing.T, publicDID string, svc *diddoc.Service) *Invitation {
	t.Helper()

	i := &Invitation{
		ID:   uuid.New().String(),
		Type: InvitationMsgType,
		DID:  publicDID,
	}

	if svc != nil {
		if svc.Type == didCommV2ServiceType {
			i.RecipientKeys = svc.RecipientKeys
			uri, err := svc.ServiceEndpoint.URI()
			require.NoError(t, err)

			i.ServiceEndpoint = uri

			routingKeys, err := svc.ServiceEndpoint.RoutingKeys()
			require.NoError(t, err)

			i.RoutingKeys = routingKeys
		} else {
			var err error

			i.RecipientKeys = svc.RecipientKeys
			i.ServiceEndpoint, err = svc.ServiceEndpoint.URI()
			require.NoError(t, err)
			i.RoutingKeys = svc.RoutingKeys
		}
	}

	return i
}

func newOOBInvite(accept []string, target interface{}) *OOBInvitation {
	return &OOBInvitation{
		ID:                uuid.New().String(),
		Type:              oobMsgType,
		ThreadID:          uuid.New().String(),
		TheirLabel:        "test",
		Target:            target,
		MediaTypeProfiles: accept,
	}
}

func newServiceBlock(recKeys, routingKeys []string, didCommServiceVType string) *diddoc.Service {
	var (
		sp                   commonmodel.Endpoint
		didCommV1RoutingKeys []string
	)

	switch didCommServiceVType {
	case didCommV2ServiceType:
		sp = commonmodel.NewDIDCommV2Endpoint([]commonmodel.DIDCommV2Endpoint{
			{URI: "http://test.com", Accept: []string{transport.MediaTypeDIDCommV2Profile}, RoutingKeys: routingKeys},
		})
	default:
		sp = commonmodel.NewDIDCommV1Endpoint("http://test.com")
		didCommV1RoutingKeys = routingKeys
	}

	svc := &diddoc.Service{
		ID:              uuid.New().String(),
		Type:            didCommServiceVType,
		RecipientKeys:   recKeys,
		ServiceEndpoint: sp,
	}

	if didCommServiceVType == didCommServiceType {
		svc.Accept = []string{transport.MediaTypeRFC0019EncryptedEnvelope}
		svc.RoutingKeys = didCommV1RoutingKeys
	}

	return svc
}

func connRecorder(t *testing.T, p provider) *connection.Recorder {
	s, err := connection.NewRecorder(p)
	require.NoError(t, err)

	return s
}
