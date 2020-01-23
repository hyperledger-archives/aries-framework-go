/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
)

const (
	jsonID       = "@id"
	jsonType     = "@type"
	jsonThread   = "~thread"
	jsonThreadID = "thid"
)

// Header helper structure which keeps reusable fields
// Deprecated: Use DIDCommMsg instead of Header
// TODO: Remove deprecated Header structure https://github.com/hyperledger/aries-framework-go/issues/1075
type Header struct {
	ID     string           `json:"@id"`
	Thread decorator.Thread `json:"~thread"`
	Type   string           `json:"@type"`
}

// DIDCommMsgMap did comm msg
type DIDCommMsgMap map[string]interface{}

// NewDIDCommMsgMap returns DIDCommMsg with Header
func NewDIDCommMsgMap(payload []byte) (DIDCommMsgMap, error) {
	var msg DIDCommMsgMap

	err := json.Unmarshal(payload, &msg)
	if err != nil {
		return nil, fmt.Errorf("invalid payload data format: %w", err)
	}

	return msg, nil
}

// ThreadID returns msg ~thread.thid if there is no ~thread.thid returns msg @id
// message is invalid if ~thread.thid exist and @id is absent
func (m DIDCommMsgMap) ThreadID() (string, error) {
	if m == nil {
		return "", ErrInvalidMessage
	}

	msgID := m.ID()
	thread, ok := m[jsonThread].(map[string]interface{})

	if ok && thread[jsonThreadID] != nil {
		var thID string
		if v, ok := thread[jsonThreadID].(string); ok {
			thID = v
		}

		// if message has ~thread.thid but @id is absent this is invalid message
		if len(thID) > 0 && msgID == "" {
			return "", ErrInvalidMessage
		}

		if len(thID) > 0 {
			return thID, nil
		}
	}

	// we need to return it only if there is no ~thread.thid
	if len(msgID) > 0 {
		return msgID, nil
	}

	return "", ErrThreadIDNotFound
}

// Type returns the message type
func (m DIDCommMsgMap) Type() string {
	if m == nil || m[jsonType] == nil {
		return ""
	}

	res, ok := m[jsonType].(string)
	if !ok {
		return ""
	}

	return res
}

// ID returns the message id
func (m DIDCommMsgMap) ID() string {
	if m == nil || m[jsonID] == nil {
		return ""
	}

	res, ok := m[jsonID].(string)
	if !ok {
		return ""
	}

	return res
}

// Decode converts message to  struct
func (m DIDCommMsgMap) Decode(v interface{}) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: func(rt1 reflect.Type, rt2 reflect.Type, v interface{}) (interface{}, error) {
			if rt1.Kind() == reflect.String && rt2 == reflect.TypeOf(time.Time{}) {
				return time.Parse(time.RFC3339, v.(string))
			}

			if rt1.Kind() == reflect.String && rt2.Kind() == reflect.Slice {
				return base64.StdEncoding.DecodeString(v.(string))
			}

			return v, nil
		},
		WeaklyTypedInput: true,
		Result:           v,
		TagName:          "json",
	})
	if err != nil {
		return err
	}

	return decoder.Decode(m)
}
