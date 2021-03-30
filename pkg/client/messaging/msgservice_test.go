/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messaging

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

func TestMsgService_AcceptAndName(t *testing.T) {
	tests := []struct {
		name     string
		args     *testArgs
		testdata []struct {
			msgtype string
			purpose []string
			result  bool
		}
	}{
		{
			name: "msgService accept with message type and purpose",
			args: &testArgs{Name: "test-01", Type: "msg-type-01", Purpose: []string{"prp-01-01", "prp-01-02"}},
			testdata: []struct {
				msgtype string
				purpose []string
				result  bool
			}{
				{
					"msg-type-01", []string{"prp-01-01", "prp-01-02"}, true,
				},
				{
					"msg-type-01", []string{"prp-01-02"}, true,
				},
				{
					"msg-type-01", []string{"prp-01-01"}, true,
				},
				{

					"msg-type-01", []string{"prp-01-01", "prp-01-03", "prp-01-04"}, true,
				},
				{
					"", []string{"prp-01-01", "prp-01-02"}, false,
				},
				{
					"", []string{"prp-01-02"}, false,
				},
				{
					"msg-type-01", nil, false,
				},
				{
					"msg-type-02", []string{"prp-02-01", "prp-02-02"}, false,
				},
			},
		},
		{
			name: "msgService accept success with only purposes",
			args: &testArgs{Name: "test-01", Purpose: []string{"prp-01-01", "prp-01-02"}},
			testdata: []struct {
				msgtype string
				purpose []string
				result  bool
			}{
				{

					"msg-type-01", []string{"prp-01-01", "prp-01-02"}, true,
				},
				{
					"msg-type-01", []string{"prp-01-02"}, true,
				},
				{
					"msg-type-01", []string{"prp-01-01"}, true,
				},
				{
					"msg-type-01", []string{"prp-01-01", "prp-01-03", "prp-01-04"}, true,
				},
				{
					"", []string{"prp-01-01", "prp-01-02"}, true,
				},
				{
					"", []string{"prp-01-02"}, true,
				},
				{
					"", []string{"prp-02-01", "prp-02-02"}, false,
				},
				{
					"msg-type-01", nil, false,
				},
				{
					"msg-type-02", []string{"prp-02-01", "prp-02-02"}, false,
				},
			},
		},
		{
			name: "msgService accept success with only message type",
			args: &testArgs{Name: "test-01", Type: "msg-type-01"},
			testdata: []struct {
				msgtype string
				purpose []string
				result  bool
			}{
				{
					"msg-type-01", []string{"prp-01-01", "prp-01-02"}, true,
				},
				{
					"msg-type-01", []string{"prp-01-02"}, true,
				},
				{
					"", []string{"prp-01-01", "prp-01-02"}, false,
				},
				{
					"", []string{"prp-01-02"}, false,
				},
				{
					"msg-type-02", nil, false,
				},
			},
		},
		{
			name: "msgService accept failure with no criteria",
			args: &testArgs{Name: "test-01"},
			testdata: []struct {
				msgtype string
				purpose []string
				result  bool
			}{
				{
					"msg-type-01", []string{"prp-01-01", "prp-01-02"}, false,
				},
				{
					"msg-type-01", []string{"prp-01-02"}, false,
				},
				{
					"", []string{"prp-01-01", "prp-01-02"}, false,
				},
				{
					"msg-type-02", nil, false,
				},
			},
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			msgsvc := newMessageService(tc.args.Name, tc.args.Type, tc.args.Purpose, nil)
			require.NotNil(t, msgsvc)
			require.Equal(t, tc.args.Name, msgsvc.Name())

			for _, testdata := range tc.testdata {
				require.Equal(t, testdata.result, msgsvc.Accept(testdata.msgtype, testdata.purpose),
					"test failed header[%s,%s] and criteria[%s]; expected[%v]",
					testdata.msgtype, testdata.purpose, tc.args, testdata.result)
			}
		})
	}
}

func TestMsgService_HandleInbound(t *testing.T) {
	const (
		sampleName = "sample-msgsvc-01"
		myDID      = "sample-mydid-01"
		theirDID   = "sample-theriDID-01"
	)

	t.Run("test message service handle inbound success with generic topic", func(t *testing.T) {
		webhookCh := make(chan []byte)

		msgsvc := newMessageService(sampleName, "", nil,
			&mockNotifier{
				NotifyFunc: func(topic string, message []byte) error {
					require.Equal(t, sampleName, topic)
					webhookCh <- message
					return nil
				},
			})
		require.NotNil(t, msgsvc)

		go func() {
			s, err := msgsvc.HandleInbound(
				service.DIDCommMsgMap{"payload": sampleName}, service.NewDIDCommContext(myDID, theirDID, nil))
			require.NoError(t, err)
			require.Empty(t, s)
		}()

		select {
		case msgBytes := <-webhookCh:
			require.NotEmpty(t, msgBytes)

			msg := mockTopic{}
			err := json.Unmarshal(msgBytes, &msg)
			require.NoError(t, err)

			require.NotNil(t, msg.Message)
			require.Equal(t, msg.Message["payload"], sampleName)
			require.Equal(t, msg.MyDID, myDID)
			require.Equal(t, msg.TheirDID, theirDID)

		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive topic [%s] to webhook", sampleName)
		}
	})

	t.Run("message service handle inbound failure", func(t *testing.T) {
		msgsvc := newMessageService("", "", nil, &mockNotifier{})
		s, err := msgsvc.HandleInbound(
			service.DIDCommMsgMap{"payload": []byte(sampleName)}, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), errTopicNotFound)
		require.Empty(t, s)
	})

	t.Run("message service handle inbound topic handle failure", func(t *testing.T) {
		const sampleErr = "sample topic error"
		topicHandle := func(service.DIDCommMsg, service.DIDCommContext) ([]byte, error) {
			return nil, fmt.Errorf(sampleErr)
		}

		msgsvc := newCustomMessageService(sampleName, "test", nil, &mockNotifier{}, topicHandle)
		s, err := msgsvc.HandleInbound(
			service.DIDCommMsgMap{"payload": []byte(sampleName)}, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErr)
		require.Empty(t, s)
	})
}

// mockTopic mock topic from message service handler.
type mockTopic struct {
	Message  service.DIDCommMsgMap `json:"message"`
	MyDID    string                `json:"mydid"`
	TheirDID string                `json:"theirdid"`
}

type testArgs struct {
	Name    string
	Purpose []string
	Type    string
}
