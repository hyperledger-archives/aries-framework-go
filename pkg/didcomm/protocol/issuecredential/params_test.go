/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

const (
	commentText   = "this is a comment"
	goalCodeText  = "goal-code"
	messageIDText = "message-id-123"
)

func previewCredV2() PreviewCredential {
	return PreviewCredential{
		Type: CredentialPreviewMsgTypeV2,
		Attributes: []Attribute{
			{
				Name:     "attribute 1",
				MimeType: "plaintext",
				Value:    "foo bar",
			},
			{
				Name:     "attribute 2",
				MimeType: "application/json",
				Value:    `{"foo":"bar"}`,
			},
		},
	}
}

func previewCredV3(t *testing.T) map[string]interface{} {
	t.Helper()

	prev := PreviewCredentialV3{
		Type: CredentialPreviewMsgTypeV3,
		ID:   "bar-baz-qux",
		Body: IssueCredentialV3Body{
			GoalCode:      "goal-code",
			ReplacementID: "blah-id",
			Comment:       commentText,
		},
	}

	prevBytes, err := json.Marshal(&prev)
	require.NoError(t, err)

	prevMap := map[string]interface{}{}

	require.NoError(t, json.Unmarshal(prevBytes, &prevMap))

	return prevMap
}

func formatList() []Format {
	return []Format{
		{
			AttachID: "attach-1",
			Format:   "foo",
		},
	}
}

func attachV1List() []decorator.Attachment {
	return []decorator.Attachment{
		{
			ID:   "attach-1",
			Data: decorator.AttachmentData{},
		},
	}
}

func attachV2List() []decorator.AttachmentV2 {
	return []decorator.AttachmentV2{
		{
			ID:   "attach-1",
			Data: decorator.AttachmentData{},
		},
	}
}

func TestProposeCredentialParams(t *testing.T) {
	t.Run("from&to v2", func(t *testing.T) {
		src := ProposeCredentialV2{
			Type:               ProposeCredentialMsgTypeV2,
			Comment:            commentText,
			CredentialProposal: previewCredV2(),
			Formats:            formatList(),
			FiltersAttach:      attachV1List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := ProposeCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV2()

		require.Equal(t, &src, dst)
	})

	t.Run("from&to v3", func(t *testing.T) {
		src := ProposeCredentialV3{
			Type: ProposeCredentialMsgTypeV3,
			ID:   messageIDText,
			Body: ProposeCredentialV3Body{
				GoalCode:          goalCodeText,
				Comment:           commentText,
				CredentialPreview: previewCredV3(t),
			},
			Attachments: attachV2List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := ProposeCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV3()

		require.Equal(t, &src, dst)
	})
}

func TestOfferCredentialParams(t *testing.T) {
	t.Run("from&to v2", func(t *testing.T) {
		src := OfferCredentialV2{
			Type:              OfferCredentialMsgTypeV2,
			Comment:           commentText,
			CredentialPreview: previewCredV2(),
			Formats:           formatList(),
			OffersAttach:      attachV1List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := OfferCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV2()

		require.Equal(t, &src, dst)
	})

	t.Run("from&to v3", func(t *testing.T) {
		src := OfferCredentialV3{
			Type: OfferCredentialMsgTypeV3,
			ID:   messageIDText,
			Body: OfferCredentialV3Body{
				GoalCode:          goalCodeText,
				Comment:           commentText,
				ReplacementID:     "replace-me-1",
				CredentialPreview: previewCredV3(t),
			},
			Attachments: attachV2List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := OfferCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV3()

		require.Equal(t, &src, dst)
	})
}

func TestRequestCredentialParams(t *testing.T) {
	t.Run("from&to v2", func(t *testing.T) {
		src := RequestCredentialV2{
			Type:           RequestCredentialMsgTypeV2,
			Comment:        commentText,
			Formats:        formatList(),
			RequestsAttach: attachV1List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := RequestCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV2()

		require.Equal(t, &src, dst)
	})

	t.Run("from&to v3", func(t *testing.T) {
		src := RequestCredentialV3{
			Type: RequestCredentialMsgTypeV3,
			ID:   messageIDText,
			Body: RequestCredentialV3Body{
				GoalCode: goalCodeText,
				Comment:  commentText,
			},
			Attachments: attachV2List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := RequestCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV3()

		require.Equal(t, &src, dst)
	})
}

func TestIssueCredentialParams(t *testing.T) {
	t.Run("from&to v2", func(t *testing.T) {
		src := IssueCredentialV2{
			Type:              IssueCredentialMsgTypeV2,
			Comment:           commentText,
			Formats:           formatList(),
			CredentialsAttach: attachV1List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := IssueCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV2()

		require.Equal(t, &src, dst)
	})

	t.Run("from&to v3", func(t *testing.T) {
		src := IssueCredentialV3{
			Type: IssueCredentialMsgTypeV3,
			ID:   messageIDText,
			Body: IssueCredentialV3Body{
				GoalCode:      goalCodeText,
				ReplacementID: "replace",
				Comment:       commentText,
			},
			Attachments: attachV2List(),
		}

		srcBytes, err := json.Marshal(src)
		require.NoError(t, err)

		params := IssueCredentialParams{}

		err = json.Unmarshal(srcBytes, &params)
		require.NoError(t, err)

		dst := params.AsV3()

		require.Equal(t, &src, dst)
	})
}
