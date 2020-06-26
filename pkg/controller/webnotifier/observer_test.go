/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webnotifier

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	mocks "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/controller/webnotifier"
)

func TestObserver_RegisterAction(t *testing.T) {
	const topic = "test"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	payload := service.DIDCommAction{
		ProtocolName: "name",
		Message:      service.NewDIDCommMsgMap(struct{}{}),
		Properties:   properties{"key": "val"},
	}

	src, err := json.Marshal(Action{
		ProtocolName: payload.ProtocolName,
		Message:      payload.Message.Clone(),
		Properties:   payload.Properties.All(),
	})
	require.NoError(t, err)

	actions := make(chan service.DIDCommAction, 1)
	actions <- payload

	done := make(chan struct{})
	notifier := mocks.NewMockNotifier(ctrl)
	notifier.EXPECT().Notify(topic, src).Do(func(string, []byte) {
		close(done)
	})

	obs := NewObserver(notifier)
	obs.RegisterAction(topic, actions)

	<-done
}

func TestObserver_RegisterStateMsg(t *testing.T) {
	const topic = "test"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	payload := service.StateMsg{
		ProtocolName: "name",
		Type:         1,
		StateID:      "state",
		Msg:          service.NewDIDCommMsgMap(struct{}{}),
		Properties:   properties{"key": "val"},
	}

	src, err := json.Marshal(StateMsg{
		ProtocolName: payload.ProtocolName,
		StateID:      payload.StateID,
		Type:         postState,
		Message:      payload.Msg.Clone(),
		Properties:   payload.Properties.All(),
	})
	require.NoError(t, err)

	actions := make(chan service.StateMsg, 1)
	actions <- payload

	done := make(chan struct{})
	notifier := mocks.NewMockNotifier(ctrl)
	notifier.EXPECT().Notify(topic, src).Do(func(string, []byte) {
		close(done)
	})

	obs := NewObserver(notifier)
	obs.RegisterStateMsg(topic, actions)

	<-done
}

type properties map[string]interface{}

func (p properties) All() map[string]interface{} {
	return p
}
