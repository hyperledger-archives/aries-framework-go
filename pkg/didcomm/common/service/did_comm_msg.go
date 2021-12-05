/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	jsonIDV1           = "@id"
	jsonIDV2           = "id"
	jsonTypeV1         = "@type"
	jsonTypeV2         = "type"
	jsonThread         = "~thread"
	jsonThreadID       = "thid"
	jsonParentThreadID = "pthid"
	jsonMetadata       = "_internal_metadata"

	basePIURI = "https://didcomm.org/"
	oldPIURI  = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/"
)

// Version represents DIDComm protocol version.
type Version string

// DIDComm versions.
const (
	V1 Version = "v1"
	V2 Version = "v2"
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

	// Interop: accept old PIURI when it's used, as we handle backwards-compatibility at a more fine-grained level.
	_, ok := msg[jsonTypeV1]
	if typ := msg.Type(); typ != "" && ok {
		msg[jsonTypeV1] = strings.Replace(typ, oldPIURI, basePIURI, 1)
	}

	return msg, nil
}

// IsDIDCommV2 returns true iff the message is a DIDComm/v2 message, false iff the message is a DIDComm/v1 message,
// and an error if neither case applies.
func IsDIDCommV2(msg *DIDCommMsgMap) (bool, error) {
	_, hasIDV2 := (*msg)["id"]
	_, hasTypeV2 := (*msg)["type"]
	// TODO: some present-proof v3 messages forget to include the body, enable the hasBodyV2 check when that is fixed.
	// TODO: see issue: https://github.com/hyperledger/aries-framework-go/issues/3039
	// _, hasBodyV2 := (*msg)["body"]

	if hasIDV2 || hasTypeV2 /* && hasBodyV2 */ {
		return true, nil
	}

	_, hasIDV1 := (*msg)["@id"]
	_, hasTypeV1 := (*msg)["@type"]

	if hasIDV1 || hasTypeV1 {
		return false, nil
	}

	return false, fmt.Errorf("not a valid didcomm v1 or v2 message")
}

// NewDIDCommMsgMap converts structure(model) to DIDCommMsgMap.
func NewDIDCommMsgMap(v interface{}) DIDCommMsgMap {
	// NOTE: do not try to replace it with mapstructure pkg
	// it doesn't work as expected, at least time.Time won't be converted
	msg := toMap(v)

	// sets empty metadata
	msg[jsonMetadata] = map[string]interface{}{}

	_, hasIDV1 := msg["@id"]
	_, hasTypeV1 := msg["@type"]
	_, hasIDV2 := msg["id"]
	_, hasTypeV2 := msg["type"]

	if hasIDV1 || hasIDV2 {
		return msg
	}

	if hasTypeV2 && !hasIDV2 {
		msg["id"] = uuid.New().String()
	} else if hasTypeV1 && !hasIDV1 {
		msg["@id"] = uuid.New().String()
	}

	return msg
}

// ThreadID returns msg ~thread.thid if there is no ~thread.thid returns msg @id
// message is invalid if ~thread.thid exist and @id is absent.
func (m DIDCommMsgMap) ThreadID() (string, error) {
	if m == nil {
		return "", ErrInvalidMessage
	}

	thid, err := m.threadIDV1()
	if err == nil || !errors.Is(err, ErrThreadIDNotFound) {
		return thid, err
	}

	return m.threadIDV2()
}

func (m DIDCommMsgMap) threadIDV2() (string, error) {
	id := m.idV2()

	threadID, ok := m[jsonThreadID].(string)
	if ok && threadID != "" {
		if id == "" {
			return "", ErrInvalidMessage
		}

		return threadID, nil
	}

	if id != "" {
		return id, nil
	}

	return "", ErrThreadIDNotFound
}

func (m DIDCommMsgMap) threadIDV1() (string, error) {
	msgID := m.idV1()
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

func (m DIDCommMsgMap) typeV1() string {
	if m == nil || m[jsonTypeV1] == nil {
		return ""
	}

	res, ok := m[jsonTypeV1].(string)
	if !ok {
		return ""
	}

	return res
}

func (m DIDCommMsgMap) typeV2() string {
	if m == nil || m[jsonTypeV2] == nil {
		return ""
	}

	res, ok := m[jsonTypeV2].(string)
	if !ok {
		return ""
	}

	return res
}

// Type returns the message type.
func (m DIDCommMsgMap) Type() string {
	if val := m.typeV1(); val != "" {
		return val
	}

	return m.typeV2()
}

// ParentThreadID returns the message parent threadID.
func (m DIDCommMsgMap) ParentThreadID() string {
	if m == nil {
		return ""
	}

	parentThreadID, ok := m[jsonParentThreadID].(string)
	if ok && parentThreadID != "" {
		return parentThreadID
	}

	if m[jsonThread] == nil {
		return ""
	}

	if thread, ok := m[jsonThread].(map[string]interface{}); ok && thread != nil {
		if pthID, ok := thread[jsonParentThreadID].(string); ok && pthID != "" {
			return pthID
		}
	}

	return ""
}

func (m DIDCommMsgMap) idV1() string {
	if m == nil || m[jsonIDV1] == nil {
		return ""
	}

	res, ok := m[jsonIDV1].(string)
	if !ok {
		return ""
	}

	return res
}

func (m DIDCommMsgMap) idV2() string {
	if m == nil || m[jsonIDV2] == nil {
		return ""
	}

	res, ok := m[jsonIDV2].(string)
	if !ok {
		return ""
	}

	return res
}

// ID returns the message id.
func (m DIDCommMsgMap) ID() string {
	if val := m.idV1(); val != "" {
		return val
	}

	return m.idV2()
}

// Opt represents an option.
type Opt func(o *options)

type options struct {
	V Version
}

func getOptions(opts ...Opt) *options {
	o := &options{}

	for i := range opts {
		opts[i](o)
	}

	if o.V == "" {
		o.V = V1
	}

	return o
}

// WithVersion specifies which version to use.
func WithVersion(v Version) Opt {
	return func(o *options) {
		o.V = v
	}
}

// SetID sets the message id.
func (m DIDCommMsgMap) SetID(id string, opts ...Opt) {
	if m == nil {
		return
	}

	o := getOptions(opts...)

	if o.V == V2 {
		m[jsonIDV2] = id

		return
	}

	m[jsonIDV1] = id
}

// SetThread sets the message thread.
func (m DIDCommMsgMap) SetThread(thid, pthid string, opts ...Opt) {
	if m == nil {
		return
	}

	if thid == "" && pthid == "" {
		return
	}

	o := getOptions(opts...)

	if o.V == V2 {
		if thid != "" {
			m[jsonThreadID] = thid
		}

		if pthid != "" {
			m[jsonParentThreadID] = pthid
		}

		return
	}

	thread := map[string]interface{}{}

	if thid != "" {
		thread[jsonThreadID] = thid
	}

	if pthid != "" {
		thread[jsonParentThreadID] = pthid
	}

	m[jsonThread] = thread
}

// UnsetThread unsets thread.
func (m DIDCommMsgMap) UnsetThread() {
	if m == nil {
		return
	}

	delete(m, jsonThread)
	delete(m, jsonThreadID)
	delete(m, jsonParentThreadID)
}

// Decode converts message to  struct.
func (m DIDCommMsgMap) Decode(v interface{}) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       decodeHook,
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
	}

	return val.Interface()
}

func decodeHook(rt1, rt2 reflect.Type, v interface{}) (interface{}, error) {
	if rt1.Kind() == reflect.String {
		if rt2 == reflect.TypeOf(time.Time{}) {
			return time.Parse(time.RFC3339, v.(string))
		}

		if rt2.Kind() == reflect.Slice && rt2.Elem().Kind() == reflect.Uint8 {
			return base64.StdEncoding.DecodeString(v.(string))
		}
	}

	if rt1.Kind() == reflect.Map && rt2.Kind() == reflect.Slice && rt2.Elem().Kind() == reflect.Uint8 {
		return json.Marshal(v)
	}

	if rt2 == reflect.TypeOf(did.Doc{}) {
		didDoc, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("error remarshaling to json: %w", err)
		}

		return did.ParseDocument(didDoc)
	}

	return v, nil
}
