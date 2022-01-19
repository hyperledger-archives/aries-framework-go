/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/client/outofband"
)

const (
	testID     = "abc123"
	testTypeV1 = "https://didcomm.org/out-of-band/1.0/invitation"
	testTypeV2 = "https://didcomm.org/out-of-band/2.0/invitation"
)

func v1Message(id, typ string, attached []string) string {
	template := `{
	"@id": "%s",
	"@type": "%s",
	"request~attach":[%s]
}`

	attachments := make([]string, len(attached))

	for i := 0; i < len(attached); i++ {
		attachments[i] = fmt.Sprintf(`{
	"data":{
		"base64":"%s"
	}
}`, base64.StdEncoding.EncodeToString([]byte(attached[i])))
	}

	reqs := strings.Join(attachments, ",")

	return fmt.Sprintf(template, id, typ, reqs)
}

func v2Message(id, typ string, attached []string) string {
	template := `{
	"id": "%s",
	"type": "%s",
	"attachments":[%s]
}`

	attachments := make([]string, len(attached))

	for i := 0; i < len(attached); i++ {
		attachments[i] = fmt.Sprintf(`{
	"data":{
		"base64":"%s"
	}
}`, base64.StdEncoding.EncodeToString([]byte(attached[i])))
	}

	reqs := strings.Join(attachments, ",")

	return fmt.Sprintf(template, id, typ, reqs)
}

func TestGenericInvitation_UnmarshalJSON(t *testing.T) {
	t.Run("success: from empty invitation", func(t *testing.T) {
		rawV1 := "{}"

		invitation := GenericInvitation{}
		err := json.Unmarshal([]byte(rawV1), &invitation)
		require.NoError(t, err)
	})

	t.Run("success: from v1 invitation", func(t *testing.T) {
		attachments := []string{"lorem", "ipsum"}

		rawV1 := v1Message(testID, testTypeV1, attachments)

		invitation := GenericInvitation{}
		err := json.Unmarshal([]byte(rawV1), &invitation)
		require.NoError(t, err)
		require.Equal(t, testID, invitation.ID)
		require.Equal(t, testTypeV1, invitation.Type)
		require.Len(t, invitation.Requests, len(attachments))

		for i, expected := range attachments {
			data, err := invitation.Requests[i].Data.Fetch()
			require.NoError(t, err)

			actual := string(data)
			require.Equal(t, expected, actual)
		}
	})

	t.Run("success: from v2 invitation", func(t *testing.T) {
		attachments := []string{"lorem", "ipsum"}

		rawV2 := v2Message(testID, testTypeV1, attachments)

		invitation := GenericInvitation{}
		err := json.Unmarshal([]byte(rawV2), &invitation)
		require.NoError(t, err)
		require.Equal(t, testID, invitation.ID)
		require.Equal(t, testTypeV1, invitation.Type)
		require.Len(t, invitation.Requests, len(attachments))

		for i, expected := range attachments {
			data, err := invitation.Requests[i].Data.Fetch()
			require.NoError(t, err)

			actual := string(data)
			require.Equal(t, expected, actual)
		}
	})

	t.Run("failure: unmarshal error", func(t *testing.T) {
		invitation := GenericInvitation{}
		err := json.Unmarshal([]byte("uh oh"), &invitation)
		require.Error(t, err)

		err = json.Unmarshal([]byte(`{"id":["shouldn't'", "be", "a", "list"]}`), &invitation)
		require.Error(t, err)
	})
}

func TestGenericInvitation_MarshalJSON(t *testing.T) {
	t.Run("success: v1", func(t *testing.T) {
		attachments := []string{"lorem", "ipsum"}

		rawV1 := []byte(v1Message(testID, testTypeV1, attachments))

		v1Inv := outofband.Invitation{}

		require.NoError(t, json.Unmarshal(rawV1, &v1Inv))

		var err error
		rawV1, err = json.Marshal(&v1Inv)
		require.NoError(t, err)

		expected := map[string]interface{}{}
		actual := map[string]interface{}{}

		require.NoError(t, json.Unmarshal(rawV1, &expected))

		invitation := GenericInvitation{}
		err = json.Unmarshal(rawV1, &invitation)
		require.NoError(t, err)

		invBytes, err := invitation.MarshalJSON()
		require.NoError(t, err)

		require.NoError(t, json.Unmarshal(invBytes, &actual))

		require.Equal(t, expected, actual)
	})

	t.Run("success: from v2 invitation", func(t *testing.T) {
		attachments := []string{"lorem", "ipsum"}

		rawV2 := []byte(v2Message(testID, testTypeV2, attachments))

		invitation := GenericInvitation{}
		err := json.Unmarshal(rawV2, &invitation)
		require.NoError(t, err)

		_, err = json.Marshal(&invitation)
		require.NoError(t, err)
	})
}

func TestGenericInvitation_AsV1(t *testing.T) {
	attachments := []string{"lorem", "ipsum"}

	rawV1 := v1Message(testID, testTypeV1, attachments)

	invitation := GenericInvitation{}
	err := json.Unmarshal([]byte(rawV1), &invitation)
	require.NoError(t, err)

	invV1 := invitation.AsV1()
	require.Equal(t, testID, invV1.ID)
	require.Equal(t, testTypeV1, invV1.Type)
	require.Len(t, invV1.Requests, len(attachments))

	for i, expected := range attachments {
		data, err := invV1.Requests[i].Data.Fetch()
		require.NoError(t, err)

		actual := string(data)
		require.Equal(t, expected, actual)
	}
}

func TestGenericInvitation_AsV2(t *testing.T) {
	attachments := []string{"lorem", "ipsum"}

	rawV1 := v2Message(testID, testTypeV2, attachments)

	invitation := GenericInvitation{}
	err := json.Unmarshal([]byte(rawV1), &invitation)
	require.NoError(t, err)

	invV2 := invitation.AsV2()
	require.Equal(t, testID, invV2.ID)
	require.Equal(t, testTypeV2, invV2.Type)
	require.Len(t, invV2.Requests, len(attachments))

	for i, expected := range attachments {
		data, err := invV2.Requests[i].Data.Fetch()
		require.NoError(t, err)

		actual := string(data)
		require.Equal(t, expected, actual)
	}
}
