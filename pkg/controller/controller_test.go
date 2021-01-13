/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package controller

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/mocks/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/defaults"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/msghandler"
)

func TestGetRESTHandlers(t *testing.T) {
	controller, err := GetRESTHandlers(&context.Provider{})
	require.Error(t, err)
	require.Contains(t, err.Error(), api.ErrSvcNotFound.Error())
	require.Nil(t, controller)
}

func TestGetCommandHandlers(t *testing.T) {
	controller, err := GetCommandHandlers(&context.Provider{})
	require.Error(t, err)
	require.Contains(t, err.Error(), api.ErrSvcNotFound.Error())
	require.Nil(t, controller)
}

func TestGetCommandHandlers_Success(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		framework, err := aries.New(defaults.WithInboundHTTPAddr(":"+
			strconv.Itoa(transportutil.GetRandomPort(3)), "", "", ""))
		require.NoError(t, err)
		require.NotNil(t, framework)

		defer func() { require.NoError(t, framework.Close()) }()

		ctx, err := framework.Context()
		require.NoError(t, err)
		require.NotNil(t, ctx)

		handlers, err := GetCommandHandlers(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
	})

	t.Run("With options", func(t *testing.T) {
		framework, err := aries.New(defaults.WithInboundHTTPAddr(":"+
			strconv.Itoa(transportutil.GetRandomPort(3)), "", "", ""))
		require.NoError(t, err)
		require.NotNil(t, framework)

		defer func() { require.NoError(t, framework.Close()) }()

		ctx, err := framework.Context()
		require.NoError(t, err)
		require.NotNil(t, ctx)

		handlers, err := GetCommandHandlers(ctx, WithMessageHandler(msghandler.NewMockMsgServiceProvider()),
			WithAutoAccept(true), WithDefaultLabel("sample-label"),
			WithWebhookURLs("sample-wh-url"), WithNotifier(webhook.NewMockWebhookNotifier()))
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
	})
}

func TestGetRESTHandlers_Success(t *testing.T) {
	t.Run("", func(t *testing.T) {
		framework, err := aries.New(defaults.WithInboundHTTPAddr(":"+
			strconv.Itoa(transportutil.GetRandomPort(3)), "", "", ""))
		require.NoError(t, err)
		require.NotNil(t, framework)

		defer func() { require.NoError(t, framework.Close()) }()

		ctx, err := framework.Context()
		require.NoError(t, err)
		require.NotNil(t, ctx)

		handlers, err := GetRESTHandlers(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
	})
	t.Run("", func(t *testing.T) {
		framework, err := aries.New(defaults.WithInboundHTTPAddr(":"+
			strconv.Itoa(transportutil.GetRandomPort(3)), "", "", ""))
		require.NoError(t, err)
		require.NotNil(t, framework)

		defer func() { require.NoError(t, framework.Close()) }()

		ctx, err := framework.Context()
		require.NoError(t, err)
		require.NotNil(t, ctx)

		handlers, err := GetRESTHandlers(ctx, WithMessageHandler(msghandler.NewMockMsgServiceProvider()),
			WithAutoAccept(true), WithDefaultLabel("sample-label"),
			WithWebhookURLs("sample-wh-url"))
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
	})
}

func TestWithWebhookNotifierOption(t *testing.T) {
	controllerOpts := &allOpts{}

	webhookURLs := []string{"localhost:8080"}
	webhookNotifierOpt := WithWebhookURLs(webhookURLs...)

	webhookNotifierOpt(controllerOpts)

	require.Equal(t, webhookURLs, controllerOpts.webhookURLs)
}

func TestWithDefaultLabelOption(t *testing.T) {
	controllerOpts := &allOpts{}

	label := "testLabel"
	webhookNotifierOpt := WithDefaultLabel(label)

	webhookNotifierOpt(controllerOpts)

	require.Equal(t, label, controllerOpts.defaultLabel)
}

func TestWithAutoAcceptOption(t *testing.T) {
	controllerOpts := &allOpts{}

	opt := WithAutoAccept(true)

	opt(controllerOpts)

	require.Equal(t, true, controllerOpts.autoAccept)
}

func TestWithMessageHandler(t *testing.T) {
	controllerOpts := &allOpts{}

	opt := WithMessageHandler(msghandler.NewMockMsgServiceProvider())

	opt(controllerOpts)

	require.NotNil(t, controllerOpts.msgHandler)
}
