/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messenger"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/introduce"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	serviceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/common/service"
	dispatcherMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengerMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	introduceMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/didcomm/protocol/introduce"
	storageMocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/spi/storage"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// Alice always plays introducer role.
	Alice = "Alice"
	// Bob always plays introducee (first) role.
	Bob = "Bob"
	// Bob always plays introducee (second) role.
	Carol = "Carol"
)

func TestService_Initialize(t *testing.T) {
	t.Run("success: already initialized", func(t *testing.T) {
		prov := &protocol.MockProvider{}

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		svc := agentSetup(t, "agent", ctrl, map[string]chan payload{})

		require.NoError(t, svc.Initialize(prov))
	})

	t.Run("fail: provider of wrong type", func(t *testing.T) {
		prov := "this is not a provider"

		svc := introduce.Service{}

		err := svc.Initialize(prov)

		require.Error(t, err)
		require.Contains(t, err.Error(), "expected provider of type")
	})
}

type props interface {
	PIID() string
	MyDID() string
	TheirDID() string
}

// payload represents a transport message structure.
type payload struct {
	msg      []byte
	myDID    string
	theirDID string
}

func agentSetup(t *testing.T, agent string, ctrl *gomock.Controller, tr map[string]chan payload) *introduce.Service {
	t.Helper()

	storageProvider := mem.NewProvider()
	didSvc := serviceMocks.NewMockEvent(ctrl)
	didSvc.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	outbound := dispatcherMocks.NewMockOutbound(ctrl)
	outbound.EXPECT().
		SendToDID(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(msg interface{}, myDID, theirDID string) error {
			src, err := json.Marshal(msg)
			require.NoError(t, err)

			tr[theirDID] <- payload{
				msg:      src,
				myDID:    theirDID,
				theirDID: myDID,
			}

			return nil
		}).AnyTimes()

	mProvider := messengerMocks.NewMockProvider(ctrl)
	mProvider.EXPECT().StorageProvider().Return(storageProvider)
	mProvider.EXPECT().OutboundDispatcher().Return(outbound)

	provider := introduceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
	provider.EXPECT().Service(gomock.Any()).Return(didSvc, nil)

	msgSvc, err := messenger.NewMessenger(mProvider)
	require.NoError(t, err)

	provider.EXPECT().Messenger().Return(msgSvc)

	svc, err := introduce.New(provider)
	require.NoError(t, err)

	go func() {
		for {
			select {
			case msg := <-tr[agent]:
				didMap, err := service.ParseDIDCommMsgMap(msg.msg)
				require.NoError(t, err)

				if didMap.Type() == outofband.InvitationMsgType {
					require.NoError(t, svc.OOBMessageReceived(service.StateMsg{
						Type:    service.PreState,
						StateID: "initial",
						Msg:     didMap,
					}))

					continue
				}

				require.NoError(t, msgSvc.HandleInbound(didMap, service.NewDIDCommContext(msg.myDID, msg.theirDID, nil)))
				_, err = svc.HandleInbound(didMap, service.NewDIDCommContext(msg.myDID, msg.theirDID, nil))
				require.NoError(t, err)
			case <-time.After(time.Second):
				return
			}
		}
	}()

	return svc
}

type (
	checkEvent  func(service.StateMsg)
	checkAction func(service.DIDCommAction)
)

func handle(t *testing.T, agent string, done chan struct{}, svc *introduce.Service, ce checkEvent, ca checkAction) {
	t.Helper()

	events := make(chan service.StateMsg)
	require.NoError(t, svc.RegisterMsgEvent(events))

	done <- struct{}{}

	go func() {
		defer func() { <-done }()

		for {
			select {
			case event := <-events:
				ce(event)
			case <-time.After(time.Second):
				t.Errorf("[%s] timeout waiting for state msg", agent)
				return
			}
		}
	}()

	actions := make(chan service.DIDCommAction)
	require.NoError(t, svc.RegisterActionEvent(actions))

	done <- struct{}{}

	go func() {
		defer func() { <-done }()

		if ca == nil {
			return
		}

		for {
			select {
			case action := <-actions:
				ca(action)
			case <-time.After(time.Second):
				t.Errorf("[%s] timeout waiting for DIDCommAction", agent)
				return
			}
		}
	}()
}

func checkStateMsg(t *testing.T, agent string, expected ...string) checkEvent {
	t.Helper()

	var i int

	return func(msg service.StateMsg) {
		if msg.StateID != expected[i] {
			t.Errorf("[%s] got %s, expected %s", agent, msg.StateID, expected[i])
		}

		i++

		if len(expected) == i {
			runtime.Goexit()
		}
	}
}

type action struct {
	Expected string
	Opt      interface{}
}

func checkDIDCommAction(t *testing.T, agent string, expected ...action) checkAction {
	var i int

	return func(action service.DIDCommAction) {
		if action.Message.Type() != expected[i].Expected {
			t.Errorf("[%s] got %s, expected %s", agent, action.Message.Type(), expected[i])
		}

		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.NotEmpty(t, properties.MyDID())
		require.NotEmpty(t, properties.TheirDID())

		action.Continue(expected[i].Opt)

		i++

		if len(expected) == i {
			runtime.Goexit()
		}
	}
}

func wait(t *testing.T, done chan struct{}) {
	for i := 0; i < len(done); i++ {
		select {
		case done <- struct{}{}:
		case <-time.After(time.Second * 2):
			t.Error("timeout")
		}
	}
}

// Bob received proposal from Alice.
// Alice received response from Bob.
// Bob received invitation from Alice.
func TestService_SkipProposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType}))

	proposal := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	introduce.WrapWithMetadataPublicOOBInvitation(proposal, &outofband.Invitation{
		Type: outofband.InvitationMsgType,
	})

	_, err := alice.HandleOutbound(proposal, Alice, Bob)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Carol received invitation from Alice.
// Bob received ack from Alice.
func TestService_Proposal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	alice := agentSetup(t, Alice, ctrl, transport)

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"confirming", "confirming",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Bob,
		action{
			Expected: introduce.ProposalMsgType,
			Opt: introduce.WithOOBInvitation(&outofband.Invitation{
				Type: outofband.InvitationMsgType,
			}),
		},
	))

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Carol, action{Expected: introduce.ProposalMsgType}))

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Carol received invitation from Alice.
// Bob received ack from Alice.
func TestService_ProposalActionContinue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	alice := agentSetup(t, Alice, ctrl, transport)

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"confirming", "confirming",
		"done", "done",
	), nil)

	bob := agentSetup(t, Bob, ctrl, transport)
	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), func(_ service.DIDCommAction) {
		actions, err := bob.Actions()
		require.NoError(t, err)
		require.Equal(t, 1, len(actions))

		require.Equal(t, actions[0].MyDID, Bob)
		require.Equal(t, actions[0].TheirDID, Alice)

		require.NoError(t, bob.ActionContinue(actions[0].PIID, introduce.WithOOBInvitation(&outofband.Invitation{
			Type: outofband.InvitationMsgType,
		})))

		runtime.Goexit()
	})

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Carol, action{Expected: introduce.ProposalMsgType}))

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Bob received invitation from Alice.
// Carol received ack from Alice.
func TestService_ProposalSecond(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"confirming", "confirming",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType}))

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Carol,
		action{
			Expected: introduce.ProposalMsgType,
			Opt: introduce.WithOOBInvitation(&outofband.Invitation{
				Type: outofband.InvitationMsgType,
			}),
		},
	))

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Bob received invitation from Alice.
// Carol received ack from Alice.
func TestService_ProposalSecondActionContinue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"confirming", "confirming",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType}))

	carol := agentSetup(t, Carol, ctrl, transport)
	handle(t, Carol, done, carol, checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), func(_ service.DIDCommAction) {
		actions, err := carol.Actions()
		require.NoError(t, err)
		require.Equal(t, 1, len(actions))

		require.Equal(t, actions[0].MyDID, Carol)
		require.Equal(t, actions[0].TheirDID, Alice)

		require.NoError(t, carol.ActionContinue(actions[0].PIID, introduce.WithOOBInvitation(&outofband.Invitation{
			Type: outofband.InvitationMsgType,
		})))

		runtime.Goexit()
	})

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Carol received problem-report from Alice ( no invitation ).
// Bob received problem-report from Alice ( no invitation ).
func TestService_ProposalNoInvitation(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"abandoning", "abandoning",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType},
		action{Expected: introduce.ProblemReportMsgType}))

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Carol, action{Expected: introduce.ProposalMsgType},
		action{Expected: introduce.ProblemReportMsgType}))

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Alice received response from Bob.
func TestService_SkipProposalStopIntroducee(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(action service.DIDCommAction) {
		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Bob)
		require.Equal(t, properties.TheirDID(), Alice)

		action.Stop(errors.New("hmm... I don't wanna know her"))
		runtime.Goexit()
	})

	proposal := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	introduce.WrapWithMetadataPublicOOBInvitation(proposal, &outofband.Invitation{
		Type: outofband.InvitationMsgType,
	})

	_, err := alice.HandleOutbound(proposal, Alice, Bob)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Alice received response from Bob.
func TestService_SkipProposalActionStopIntroducee(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)
	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), nil)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(_ service.DIDCommAction) {
		actions, err := bob.Actions()
		require.NoError(t, err)
		require.Equal(t, 1, len(actions))

		require.Equal(t, actions[0].MyDID, Bob)
		require.Equal(t, actions[0].TheirDID, Alice)

		require.NoError(t, bob.ActionStop(actions[0].PIID, errors.New("hmm... I don't wanna know her")))
		runtime.Goexit()
	})

	proposal := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	introduce.WrapWithMetadataPublicOOBInvitation(proposal, &outofband.Invitation{
		Type: outofband.InvitationMsgType,
	})

	_, err := alice.HandleOutbound(proposal, Alice, Bob)
	require.NoError(t, err)
}

// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Carol received problem-report from Alice ( not approved ).
func TestService_ProposalStopIntroduceeFirst(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(action service.DIDCommAction) {
		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Bob)
		require.Equal(t, properties.TheirDID(), Alice)

		action.Stop(errors.New("hmm... I don't wanna know her"))
		runtime.Goexit()
	})

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Carol, action{Expected: introduce.ProposalMsgType},
		action{Expected: introduce.ProblemReportMsgType}))

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Carol received proposal from Alice.
// Bob received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Bob received problem-report from Alice ( not approved ).
func TestService_ProposalStopIntroduceeSecond(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType},
		action{Expected: introduce.ProblemReportMsgType}))

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(action service.DIDCommAction) {
		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Carol)
		require.Equal(t, properties.TheirDID(), Alice)

		action.Stop(errors.New("hmm... I don't wanna know him"))
		runtime.Goexit()
	})

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Carol received proposal from Alice.
// Bob received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Bob received problem-report from Alice ( not approved ).
func TestService_ProposalActionStopIntroduceeSecond(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)
	carol := agentSetup(t, Carol, ctrl, transport)

	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), nil)

	handle(t, Bob, done, agentSetup(t, Bob, ctrl, transport), checkStateMsg(t, Bob,
		"deciding", "deciding",
		"waiting", "waiting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType},
		action{Expected: introduce.ProblemReportMsgType}))

	handle(t, Carol, done, carol, checkStateMsg(t, Carol,
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(_ service.DIDCommAction) {
		actions, err := carol.Actions()
		require.NoError(t, err)
		require.Equal(t, 1, len(actions))

		require.Equal(t, actions[0].MyDID, Carol)
		require.Equal(t, actions[0].TheirDID, Alice)

		require.NoError(t, carol.ActionStop(actions[0].PIID, errors.New("hmm... I don't wanna know him")))
		runtime.Goexit()
		runtime.Goexit()
	})

	proposal1 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Carol}})
	proposal2 := introduce.CreateProposal(&introduce.Recipient{To: &introduce.To{Name: Bob}})

	introduce.WrapWithMetadataPIID(proposal1, proposal2)

	_, err := alice.HandleOutbound(proposal1, Alice, Bob)
	require.NoError(t, err)

	_, err = alice.HandleOutbound(proposal2, Alice, Carol)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Carol received invitation from Alice.
// Bob received ack from Alice.
func TestService_ProposalWithRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"confirming", "confirming",
		"done", "done",
	), checkDIDCommAction(t, Alice,
		action{
			Expected: introduce.RequestMsgType,
			Opt: introduce.WithRecipients(&introduce.To{
				Name: Carol,
			}, &introduce.Recipient{
				To: &introduce.To{
					Name: Bob,
				},
				MyDID:    Alice,
				TheirDID: Carol,
			}),
		},
	))

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Bob,
		action{
			Expected: introduce.ProposalMsgType,
			Opt: introduce.WithOOBInvitation(&outofband.Invitation{
				Type: outofband.InvitationMsgType,
			}),
		},
	))

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Carol, action{Expected: introduce.ProposalMsgType}))

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Carol received invitation from Alice.
// Bob received ack from Alice.
func TestService_ProposalWithRequestActionContinue(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	alice := agentSetup(t, Alice, ctrl, transport)
	handle(t, Alice, done, alice, checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"confirming", "confirming",
		"done", "done",
	), func(_ service.DIDCommAction) {
		actions, err := alice.Actions()
		require.NoError(t, err)
		require.Equal(t, 1, len(actions))

		require.Equal(t, actions[0].MyDID, Alice)
		require.Equal(t, actions[0].TheirDID, Bob)

		require.NoError(t, alice.ActionContinue(actions[0].PIID, introduce.WithRecipients(&introduce.To{
			Name: Carol,
		}, &introduce.Recipient{
			To: &introduce.To{
				Name: Bob,
			},
			MyDID:    Alice,
			TheirDID: Carol,
		})))

		runtime.Goexit()
	})

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), func(commAction service.DIDCommAction) {
		actions, err := bob.Actions()
		require.NoError(t, err)
		require.Equal(t, 1, len(actions))

		require.Equal(t, actions[0].MyDID, Bob)
		require.Equal(t, actions[0].TheirDID, Alice)

		require.NoError(t, bob.ActionContinue(actions[0].PIID, introduce.WithOOBInvitation(&outofband.Invitation{
			Type: outofband.InvitationMsgType,
		})))

		runtime.Goexit()
	})

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Carol, action{Expected: introduce.ProposalMsgType}))

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Bob received invitation from Alice.
// Carol received ack from Alice.
func TestService_ProposalWithRequestSecond(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"confirming", "confirming",
		"done", "done",
	), checkDIDCommAction(t, Alice,
		action{
			Expected: introduce.RequestMsgType,
			Opt: introduce.WithRecipients(&introduce.To{
				Name: Carol,
			}, &introduce.Recipient{
				To: &introduce.To{
					Name: Bob,
				},
				MyDID:    Alice,
				TheirDID: Carol,
			}),
		},
	))

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType}))

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Carol,
		action{
			Expected: introduce.ProposalMsgType,
			Opt: introduce.WithOOBInvitation(&outofband.Invitation{
				Type: outofband.InvitationMsgType,
			}),
		},
	))

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received proposal from Alice.
// Carol received proposal from Alice.
// Alice received response from Bob.
// Alice received response from Carol.
// Carol received problem-report from Alice ( not approved ).
func TestService_ProposalWithRequestStopIntroduceeFirst(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Alice,
		action{
			Expected: introduce.RequestMsgType,
			Opt: introduce.WithRecipients(&introduce.To{
				Name: Carol,
			}, &introduce.Recipient{
				To: &introduce.To{
					Name: Bob,
				},
				MyDID:    Alice,
				TheirDID: Carol,
			}),
		},
	))

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(action service.DIDCommAction) {
		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Bob)
		require.Equal(t, properties.TheirDID(), Alice)

		action.Stop(errors.New("hmm... I don't wanna know her"))
		runtime.Goexit()
	})

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"waiting", "waiting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Carol, action{Expected: introduce.ProposalMsgType},
		action{Expected: introduce.ProblemReportMsgType}))

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Carol received proposal from Alice.
// Bob received proposal from Alice.
// Alice received response from Carol.
// Alice received response from Bob.
// Bob received problem-report from Alice ( not approved ).
func TestService_ProposalWithRequestStopIntroduceeSecond(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
		Carol: make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Alice,
		action{
			Expected: introduce.RequestMsgType,
			Opt: introduce.WithRecipients(&introduce.To{
				Name: Carol,
			}, &introduce.Recipient{
				To: &introduce.To{
					Name: Bob,
				},
				MyDID:    Alice,
				TheirDID: Carol,
			}),
		},
	))

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"deciding", "deciding",
		"waiting", "waiting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType},
		action{Expected: introduce.ProblemReportMsgType}))

	handle(t, Carol, done, agentSetup(t, Carol, ctrl, transport), checkStateMsg(t, Carol,
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(action service.DIDCommAction) {
		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Carol)
		require.Equal(t, properties.TheirDID(), Alice)

		action.Stop(errors.New("hmm... I don't wanna know him"))
		runtime.Goexit()
	})

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received problem-report from Alice ( request declined ).
func TestService_ProposalWithRequestIntroducerStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"abandoning", "abandoning",
		"done", "done",
	), func(action service.DIDCommAction) {
		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Alice)
		require.Equal(t, properties.TheirDID(), Bob)

		action.Stop(errors.New("sorry, I don't know her"))
		runtime.Goexit()
	})

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProblemReportMsgType}))

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received proposal from Alice.
// Alice received response from Bob.
// Bob received invitation from Alice.
func TestService_SkipProposalWithRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"delivering", "delivering",
		"done", "done",
	), checkDIDCommAction(t, Alice,
		action{
			Expected: introduce.RequestMsgType,
			Opt: introduce.WithPublicOOBInvitation(&outofband.Invitation{
				Type: outofband.InvitationMsgType,
			}, &introduce.To{
				Name: Carol,
			}),
		},
	))

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"deciding", "deciding",
		"waiting", "waiting",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProposalMsgType}))

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received proposal from Alice.
// Alice received response from Bob.
func TestService_SkipProposalWithRequestStopIntroducee(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"arranging", "arranging",
		"arranging", "arranging",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Alice,
		action{
			Expected: introduce.RequestMsgType,
			Opt: introduce.WithPublicOOBInvitation(&outofband.Invitation{
				Type: outofband.InvitationMsgType,
			}, &introduce.To{
				Name: Carol,
			}),
		},
	))

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"deciding", "deciding",
		"abandoning", "abandoning",
		"done", "done",
	), func(action service.DIDCommAction) {
		properties, ok := action.Properties.(props)
		require.True(t, ok)
		require.NotEmpty(t, properties.PIID())
		require.Equal(t, properties.MyDID(), Bob)
		require.Equal(t, properties.TheirDID(), Alice)

		action.Stop(errors.New("hmm... I don't wanna know her"))
		runtime.Goexit()
	})

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

// Alice received request from Bob.
// Bob received problem-report from Alice.
func TestService_ProposalWithRequestNoRecipients(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	transport := map[string]chan payload{
		Alice: make(chan payload),
		Bob:   make(chan payload),
	}

	done := make(chan struct{}, len(transport)*2)
	defer wait(t, done)

	handle(t, Alice, done, agentSetup(t, Alice, ctrl, transport), checkStateMsg(t, Alice,
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Alice,
		action{Expected: introduce.RequestMsgType},
	))

	bob := agentSetup(t, Bob, ctrl, transport)

	handle(t, Bob, done, bob, checkStateMsg(t, Bob,
		"requesting", "requesting",
		"abandoning", "abandoning",
		"done", "done",
	), checkDIDCommAction(t, Bob, action{Expected: introduce.ProblemReportMsgType}))

	_, err := bob.HandleOutbound(service.NewDIDCommMsgMap(&introduce.Request{
		Type: introduce.RequestMsgType,
		PleaseIntroduceTo: &introduce.PleaseIntroduceTo{To: introduce.To{
			Name: Carol,
		}},
	}), Bob, Alice)
	require.NoError(t, err)
}

func TestService_Accept(t *testing.T) {
	svc := &introduce.Service{}

	require.False(t, svc.Accept(""))
	require.True(t, svc.Accept(introduce.ProposalMsgType))
	require.True(t, svc.Accept(introduce.RequestMsgType))
	require.True(t, svc.Accept(introduce.ResponseMsgType))
	require.True(t, svc.Accept(introduce.AckMsgType))
	require.True(t, svc.Accept(introduce.ProblemReportMsgType))
}

func TestService_Name(t *testing.T) {
	require.Equal(t, introduce.Introduce, (&introduce.Service{}).Name())
}

func TestService_New(t *testing.T) {
	const errMsg = "test err"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("OpenStore Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, errors.New(errMsg))

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)

		svc, err := introduce.New(provider)
		require.EqualError(t, err, "test err")
		require.Nil(t, svc)
	})

	t.Run("Service Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Service(outofband.Name).Return(nil, errors.New(errMsg))

		svc, err := introduce.New(provider)
		require.EqualError(t, err, "load the out-of-band service: test err")
		require.Nil(t, svc)
	})

	t.Run("Cast Service Error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Service(outofband.Name).Return(nil, nil)

		svc, err := introduce.New(provider)
		require.EqualError(t, err, "cast service to service.Event")
		require.Nil(t, svc)
	})

	t.Run("wraps error returned during msg event registration", func(t *testing.T) {
		expected := errors.New("test")

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)
		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)

		oobService := serviceMocks.NewMockDIDComm(ctrl)
		oobService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(expected)
		provider.EXPECT().Service(outofband.Name).Return(oobService, nil)

		_, err := introduce.New(provider)
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}

func TestService_HandleOutbound(t *testing.T) {
	t.Run("Invalid state", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		raw := fmt.Sprintf(`{"state_name":%q, "wait_count":%d}`, "unknown", 1)
		store.EXPECT().Get(gomock.Any()).Return([]byte(raw), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(didService, nil)

		svc, err := introduce.New(provider)

		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))
		const errMsg = "doHandle: invalid state transition: noop -> arranging"
		_, err = svc.HandleOutbound(msg, "", "")
		require.EqualError(t, err, errMsg)
	})
}

func TestService_HandleInbound(t *testing.T) {
	t.Parallel()

	t.Run("No clients", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(nil, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		_, err = svc.HandleInbound(service.DIDCommMsgMap{}, service.EmptyDIDCommContext())
		require.EqualError(t, err, "no clients are registered to handle the message")
	})

	t.Run("Storage error", func(t *testing.T) {
		const errMsg = "test err"

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.EqualError(t, err, "doHandle: currentStateName: test err")
	})

	t.Run("Populate metadata error", func(t *testing.T) {
		const errMsg = "test err"

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.EqualError(t, err, "populate metadata: get record: test err")
	})

	t.Run("Bad transition", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Get(gomock.Any()).Return([]byte(`{"state_name":"noop","wait_count":1}`), nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(fmt.Sprintf(`{"@id":"ID","@type":%q}`, introduce.ProposalMsgType)))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.EqualError(t, err, "doHandle: invalid state transition: noop -> deciding")
	})

	t.Run("Unknown msg type error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)
		store.EXPECT().Get(gomock.Any()).Return(nil, storage.ErrDataNotFound)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

		didService := serviceMocks.NewMockDIDComm(ctrl)
		didService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(didService, nil)

		svc, err := introduce.New(provider)
		require.NoError(t, err)

		msg, err := service.ParseDIDCommMsgMap([]byte(`{"@id":"ID","@type":"unknown"}`))
		require.NoError(t, err)
		ch := make(chan service.DIDCommAction)
		require.NoError(t, svc.RegisterActionEvent(ch))

		_, err = svc.HandleInbound(msg, service.EmptyDIDCommContext())
		require.EqualError(t, err, "doHandle: nextState: unrecognized msgType: unknown")
	})
}

func TestService_ActionStop(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const errMsg = "error"

	store := storageMocks.NewMockStore(ctrl)
	store.EXPECT().Get(gomock.Any()).Return(nil, errors.New(errMsg))

	storageProvider := storageMocks.NewMockProvider(ctrl)
	storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
	storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)

	oobService := serviceMocks.NewMockDIDComm(ctrl)
	oobService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)

	provider := introduceMocks.NewMockProvider(ctrl)
	provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
	provider.EXPECT().Messenger().Return(nil)
	provider.EXPECT().Service(outofband.Name).Return(oobService, nil)

	s, err := introduce.New(provider)
	require.NoError(t, err)

	require.EqualError(t, s.ActionStop("piid", nil), "get transitional payload: store get: "+errMsg)
}

func TestOOBMessageReceived(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("ignores msg not in requested state", func(t *testing.T) {
		ignored := true
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).MaxTimes(0).DoAndReturn(
			func(string) ([]byte, error) {
				ignored = false
				return nil, nil
			},
		)
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)
		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		oobService := serviceMocks.NewMockDIDComm(ctrl)
		oobService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(oobService, nil)

		s, err := introduce.New(provider)
		require.NoError(t, err)

		err = s.OOBMessageReceived(service.StateMsg{
			Type:    service.PostState,
			StateID: "invalid",
			Msg: service.NewDIDCommMsgMap(&model.Ack{
				Thread: &decorator.Thread{
					PID: "123",
				},
			}),
		})
		require.NoError(t, err)
		require.True(t, ignored)
	})
	t.Run("ignores pre-state msgs", func(t *testing.T) {
		ignored := true
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).MaxTimes(0).DoAndReturn(
			func(string) ([]byte, error) {
				ignored = false
				return nil, nil
			},
		)
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)
		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		oobService := serviceMocks.NewMockDIDComm(ctrl)
		oobService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(oobService, nil)

		s, err := introduce.New(provider)
		require.NoError(t, err)

		err = s.OOBMessageReceived(service.StateMsg{
			Type:    service.PreState,
			StateID: "requested",
			Msg: service.NewDIDCommMsgMap(&model.Ack{
				Thread: &decorator.Thread{
					PID: "123",
				},
			}),
		})
		require.NoError(t, err)
		require.True(t, ignored)
	})
	t.Run("ignores msgs with no parent thread", func(t *testing.T) {
		ignored := true
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Get(gomock.Any()).MaxTimes(0).DoAndReturn(
			func(string) ([]byte, error) {
				ignored = false
				return nil, nil
			},
		)
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(introduce.Introduce).Return(store, nil)
		storageProvider.EXPECT().SetStoreConfig(introduce.Introduce, gomock.Any()).Return(nil)
		provider := introduceMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider).Times(2)
		provider.EXPECT().Messenger().Return(nil)
		oobService := serviceMocks.NewMockDIDComm(ctrl)
		oobService.EXPECT().RegisterMsgEvent(gomock.Any()).Return(nil)
		provider.EXPECT().Service(outofband.Name).Return(oobService, nil)

		s, err := introduce.New(provider)
		require.NoError(t, err)

		err = s.OOBMessageReceived(service.StateMsg{
			Type:    service.PostState,
			StateID: "requested",
			Msg:     service.NewDIDCommMsgMap(&model.Ack{}),
		})
		require.NoError(t, err)
		require.True(t, ignored)
	})
}
