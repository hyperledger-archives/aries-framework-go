/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/models"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/kms"
)

func getKMSController(t *testing.T) *KMS {
	a, err := getAgent()
	require.NotNil(t, a)
	require.NoError(t, err)

	controller, err := a.GetKMSController()
	require.NoError(t, err)
	require.NotNil(t, controller)

	k, ok := controller.(*KMS)
	require.Equal(t, ok, true)

	return k
}

func TestKMS_CreateKeySet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getKMSController(t)

		mockResponse := `{"keyID":"keyID","verificationMethod":"cHVibGljS2V5"}`

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[kms.CreateKeySetCommandMethod] = fakeHandler.exec

		payload := `{"keyType":"ED25519"}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.CreateKeySet(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}

func TestKMS_ImportKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		controller := getKMSController(t)

		mockResponse := emptyJSON

		fakeHandler := mockCommandRunner{data: []byte(mockResponse)}
		controller.handlers[kms.ImportKeyCommandMethod] = fakeHandler.exec

		payload := `{"kty":"OKP","kid":"kid","crv":"Ed25519","alg":"EdDSA",
"x":"jXAvdkE8oHbFat1HYkdq3FXsuPdGtdl8NhKr163kikA","d":"QlXTAvl0V7Kh7ckWXTVmdAdZZQcIdZ0yqXxwvw9QX04"}`

		req := &models.RequestEnvelope{Payload: []byte(payload)}
		resp := controller.ImportKey(req)
		require.NotNil(t, resp)
		require.Nil(t, resp.Error)
		require.Equal(t,
			mockResponse,
			string(resp.Payload))
	})
}
