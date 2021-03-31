/*
 *
 * Copyright SecureKey Technologies Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
 *
 */

package basic

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
)

func TestNewMessageService(t *testing.T) {
	t.Run("test create new MessageService success", func(t *testing.T) {
		svc, err := NewMessageService("sample-name", getMockMessageHandle())
		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("test create new MessageService error", func(t *testing.T) {
		svc, err := NewMessageService("", getMockMessageHandle())
		require.Nil(t, svc)
		require.Error(t, err)
		require.Contains(t, err.Error(), errNameAndHandleMandatory)

		svc, err = NewMessageService("sample-name", nil)
		require.Nil(t, svc)
		require.Error(t, err)
		require.Contains(t, err.Error(), errNameAndHandleMandatory)
	})
}

func TestMessageService_Name(t *testing.T) {
	t.Run("test MessageService.Name()", func(t *testing.T) {
		const sampleName = "sample-name"
		svc, err := NewMessageService("sample-name", getMockMessageHandle())
		require.NoError(t, err)
		require.NotNil(t, svc)
		require.Equal(t, svc.Name(), sampleName)
	})
}

func TestMessageService_Accept(t *testing.T) {
	t.Run("test MessageService.Accept()", func(t *testing.T) {
		svc, err := NewMessageService("sample-name", getMockMessageHandle())
		require.NoError(t, err)
		require.NotNil(t, svc)

		require.True(t, svc.Accept(MessageRequestType, nil))
		require.True(t, svc.Accept(MessageRequestType, []string{"sample-purpose001", "sample-purpose-02"}))
		require.False(t, svc.Accept("random-msg-type", nil))
		require.False(t, svc.Accept("random-msg-type", []string{"sample-purpose001", "sample-purpose-02"}))
	})
}

func TestMessageService_HandleInbound(t *testing.T) {
	const myDID = "sample-my-did"

	const theirDID = "sample-their-did"

	t.Run("test MessageService.HandleInbound()", func(t *testing.T) {
		const jsonStr = `{
			    "@id": "123456780",
			    "@type": "https://didcomm.org/basicmessage/1.0/message",
			    "~l10n": { "locale": "en" },
			    "content": "Your hovercraft is full of eels."
			}`

		testCh := make(chan struct {
			message  Message
			myDID    string
			theirDID string
		})
		handleFn := func(message Message, ctx service.DIDCommContext) error {
			testCh <- struct {
				message  Message
				myDID    string
				theirDID string
			}{
				message: message, myDID: ctx.MyDID(), theirDID: ctx.TheirDID(),
			}
			return nil
		}

		svc, err := NewMessageService("sample-name", handleFn)
		require.NoError(t, err)
		require.NotNil(t, svc)

		go func() {
			msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
			require.NoError(t, err)

			_, err = svc.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))
			require.NoError(t, err)
		}()

		select {
		case x := <-testCh:
			require.NotNil(t, x)
			require.Equal(t, x.myDID, myDID)
			require.Equal(t, x.theirDID, theirDID)
			require.Equal(t, x.message.I10n.Locale, "en")
			require.Equal(t, x.message.Content, "Your hovercraft is full of eels.")
			require.Equal(t, x.message.ID, "123456780")
		case <-time.After(2 * time.Second):
			require.Fail(t, "didn't receive basic message to handle")
		}
	})

	t.Run("test MessageService.HandleInbound() error", func(t *testing.T) {
		const sampleErr = "sample-error"
		svc, err := NewMessageService("sample-name", getMockMessageHandle())
		require.NoError(t, err)
		require.NotNil(t, svc)

		_, err = svc.HandleInbound(&mockMsg{err: fmt.Errorf(sampleErr)}, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to decode incoming DID comm message")
	})
}

func getMockMessageHandle() MessageHandle {
	return func(Message, service.DIDCommContext) error {
		return nil
	}
}

type mockMsg struct {
	*service.DIDCommMsgMap
	err error
}

func (m *mockMsg) Decode(v interface{}) error {
	return m.err
}
