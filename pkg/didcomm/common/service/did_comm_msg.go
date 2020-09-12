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
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
)

const (
	jsonID             = "@id"
	jsonType           = "@type"
	jsonThread         = "~thread"
	jsonThreadID       = "thid"
	jsonParentThreadID = "pthid"
	jsonMetadata       = "_internal_metadata"
)

// Metadata may contain additional payload for the protocol. It might be populated by the client/protocol
// for outbound messages. If metadata were populated, the messenger will automatically add it to the incoming
// messages by the threadID. If Metadata is <nil> in the outbound message the previous payload
// will be added to the incoming message. Otherwise, the payload will be rewritten.
// NOTE: Metadata is not a part of the JSON message. The payload will not be sent to another agent.
// Metadata should be used by embedding it to the model structure. e.g
// 	type A struct {
// 		Metadata `json:",squash"`
// 	}
type Metadata struct {
	Payload map[string]interface{} `json:"_internal_metadata,omitempty"`
}

// DIDCommMsgMap did comm msg.
type DIDCommMsgMap map[string]interface{}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (m *DIDCommMsgMap) UnmarshalJSON(b []byte) error {
	defer func() {
		if (*m) != nil {
			// sets empty metadata
			(*m)[jsonMetadata] = map[string]interface{}{}
		}
	}()

	return json.Unmarshal(b, (*map[string]interface{})(m))
}

// MarshalJSON implements the json.Marshaler interface.
func (m DIDCommMsgMap) MarshalJSON() ([]byte, error) {
	if m != nil {
		metadata := m[jsonMetadata]
		delete(m, jsonMetadata)

		defer func() { m[jsonMetadata] = metadata }()
	}

	return json.Marshal(map[string]interface{}(m))
}

// ParseDIDCommMsgMap returns DIDCommMsg with Header.
func ParseDIDCommMsgMap(payload []byte) (DIDCommMsgMap, error) {
	var msg DIDCommMsgMap

	err := json.Unmarshal(payload, &msg)
	if err != nil {
		return nil, fmt.Errorf("invalid payload data format: %w", err)
	}

	return msg, nil
}

// NewDIDCommMsgMap converts structure(model) to DIDCommMsgMap.
func NewDIDCommMsgMap(v interface{}) DIDCommMsgMap {
	// NOTE: do not try to replace it with mapstructure pkg
	// it doesn't work as expected, at least time.Time won't be converted
	msg := toMap(v)

	// sets empty metadata
	msg[jsonMetadata] = map[string]interface{}{}

	return msg
}

// ThreadID returns msg ~thread.thid if there is no ~thread.thid returns msg @id
// message is invalid if ~thread.thid exist and @id is absent.
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

// Metadata returns message metadata.
func (m DIDCommMsgMap) Metadata() map[string]interface{} {
	if m[jsonMetadata] == nil {
		return nil
	}

	metadata, ok := m[jsonMetadata].(map[string]interface{})
	if !ok {
		return nil
	}

	return metadata
}

// Type returns the message type.
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

// ParentThreadID returns the message parent threadID.
func (m DIDCommMsgMap) ParentThreadID() string {
	if m == nil || m[jsonThread] == nil {
		return ""
	}

	if thread, ok := m[jsonThread].(map[string]interface{}); ok && thread != nil {
		if pthID, ok := thread[jsonParentThreadID].(string); ok && pthID != "" {
			return pthID
		}
	}

	return ""
}

// ID returns the message id.
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

// SetID sets the message id.
func (m DIDCommMsgMap) SetID(id string) error {
	if m == nil {
		return ErrNilMessage
	}

	m[jsonID] = id

	return nil
}

// Decode converts message to  struct.
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

// Clone copies first level keys-values into another map (DIDCommMsgMap).
func (m DIDCommMsgMap) Clone() DIDCommMsgMap {
	if m == nil {
		return nil
	}

	msg := DIDCommMsgMap{}
	for k, v := range m {
		msg[k] = v
	}

	return msg
}

func toMap(v interface{}) map[string]interface{} {
	res := make(map[string]interface{})

	// if it is pointer returns the value
	rv := reflect.Indirect(reflect.ValueOf(v))
	for rfv, field := range mapValueStructField(rv) {
		// the default name is equal to field Name
		name := field.Name

		tags := strings.Split(field.Tag.Get(`json`), ",")
		// if tag is not empty name is equal to tag
		if tags[0] != "" {
			name = tags[0]
		}

		res[name] = convert(rfv)
	}

	return res
}

func mapValueStructField(value reflect.Value) map[reflect.Value]reflect.StructField {
	fields := make(map[reflect.Value]reflect.StructField)
	rt := value.Type()

	for i := 0; i < rt.NumField(); i++ {
		rv, sf := value.Field(i), rt.Field(i)

		tags := strings.Split(sf.Tag.Get(`json`), ",")

		// the field should be ignored according to JSON tag `json:"-"`
		if tags[0] == "-" {
			continue
		}

		// the field should be ignored if it is empty according to JSON tag `json:",omitempty"`
		// NOTE: works when omitempty it the last one
		if tags[len(tags)-1] == "omitempty" {
			if reflect.DeepEqual(reflect.Zero(rv.Type()).Interface(), rv.Interface()) {
				continue
			}
		}

		// unexported fields should be ignored as well
		if sf.PkgPath != "" {
			continue
		}

		// if it is an embedded field, we need to add it to the map
		// NOTE: for now, the only embedded structure is supported
		rv = reflect.Indirect(rv)
		if sf.Anonymous && rv.Kind() == reflect.Struct {
			// if an embedded field doesn't have a tag it means the same level
			if tags[0] == "" {
				for k, v := range mapValueStructField(rv) {
					fields[k] = v
				}

				continue
			}
		}

		fields[rv] = sf
	}

	return fields
}

func convert(val reflect.Value) interface{} {
	switch reflect.Indirect(val).Kind() {
	case reflect.Array, reflect.Slice:
		res := make([]interface{}, val.Len())
		for i := range res {
			res[i] = convert(val.Index(i))
		}

		return res
	case reflect.Map:
		res := make(map[string]interface{}, val.Len())
		for _, k := range val.MapKeys() {
			res[k.String()] = convert(val.MapIndex(k))
		}

		return res
	case reflect.Struct:
		if res := toMap(val.Interface()); len(res) != 0 {
			return res
		}

		return val.Interface()

	default:
		return val.Interface()
	}
}
