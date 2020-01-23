/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package common

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	mockwebhook "github.com/hyperledger/aries-framework-go/pkg/restapi/internal/mocks/webhook"
)

func TestMsgService_AcceptAndName(t *testing.T) {
	tests := []struct {
		name     string
		service  *RegisterMsgSvcParams
		testdata []struct {
			msgtype string
			purpose []string
			result  bool
		}
	}{
		{
			name:    "msgService accept with message type and purpose",
			service: &RegisterMsgSvcParams{Name: "test-01", Type: "msg-type-01", Purpose: []string{"prp-01-01", "prp-01-02"}},
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
			name:    "msgService accept success with only purposes",
			service: &RegisterMsgSvcParams{Name: "test-01", Purpose: []string{"prp-01-01", "prp-01-02"}},
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
			name:    "msgService accept success with only message type",
			service: &RegisterMsgSvcParams{Name: "test-01", Type: "msg-type-01"},
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
			name:    "msgService accept failure with no criteria",
			service: &RegisterMsgSvcParams{Name: "test-01"},
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
			msgsvc := newMessageService(tc.service, nil)
			require.NotNil(t, msgsvc)
			require.Equal(t, tc.service.Name, msgsvc.Name())

			for _, testdata := range tc.testdata {
				require.Equal(t, testdata.result, msgsvc.Accept(testdata.msgtype, testdata.purpose),
					"test failed header[%s,%s] and criteria[%s]; expected[%v]",
					testdata.msgtype, testdata.purpose, tc.service, testdata.result)
			}
		})
	}
}

func TestMsgService_HandleInbound(t *testing.T) {
	const sampleName = "sample-msgsvc-01"

	const myDID = "sample-mydid-01"

	const theirDID = "sample-theriDID-01"

	t.Run("message service handle inbound success", func(t *testing.T) {
		webhookCh := make(chan []byte)

		msgsvc := newMessageService(&RegisterMsgSvcParams{Name: sampleName},
			&mockwebhook.Notifier{
				NotifyFunc: func(topic string, message []byte) error {
					require.Equal(t, sampleName, topic)
					webhookCh <- message
					return nil
				},
			})
		require.NotNil(t, msgsvc)

		go func() {
			s, err := msgsvc.HandleInbound(service.DIDCommMsgMap{"payload": sampleName}, myDID, theirDID)
			require.NoError(t, err)
			require.Empty(t, s)
		}()

		select {
		case msgBytes := <-webhookCh:
			require.NotEmpty(t, msgBytes)

			msg := inboundMsg{}
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
		msgsvc := newMessageService(&RegisterMsgSvcParams{}, mockwebhook.NewMockWebhookNotifier())
		s, err := msgsvc.HandleInbound(service.DIDCommMsgMap{"payload": []byte(sampleName)}, myDID, theirDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errTopicNotFound)
		require.Empty(t, s)
	})
}
