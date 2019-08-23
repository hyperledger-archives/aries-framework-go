/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package state

import (
	"encoding/json"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	//NullState is the did-exchange protocol initial state
	NullState = "null"
	//InvitedState is the did-exchange protocol invited state
	InvitedState = "invited"
	//RequestedState is the did-exchange protocol requested state
	RequestedState = "requested"
	//RespondedState is the did-exchange protocol responded state
	RespondedState = "responded"
	//CompleteState is the did-exchange protocol completed state
	CompleteState = "completed"

	//Reqquest Types supported in Did-exchange
	invitation = "invitation"
	response   = "response"
	request    = "request"
	ack        = "ack"
)

//Context defines the DIDComm state context
type Context struct {
	Store storage.Store
	State *State
}

// New creates the new context
func New(store storage.Store, state *State) *Context {
	return &Context{
		Store: store,
		State: state,
	}
}

// DidCommState describes the internal State machine for Inviter and Invitee. Reference: https://github.com/hyperledger/aries-rfcs/blob/master/features/0023-did-exchange/chrome_2019-01-29_07-59-38.png
type DidCommState interface {
	//Handle accepts the didComm protocol message which contains string representation of invitation, exchange_request, exchange_response etc.
	Handle(msg []byte)
	//CheckState allows the user to check the state of the state machine by passing key which is concatenation of protocol, version and connection ID (for example : didexchange1.012345678900987654321)
	CheckState(key string) string
}

//State defines a didcomm state
type State struct {
	MsgType      string            `json:"@type"`
	ConnectionID string            `json:"@id"`
	ThreadID     map[string]string `json:"~thread"`
	requestType  string
	protocol     string
	version      string
	current      string
}

//Handle accepts the didComm protocol message and then set the state based on the message
func (c *Context) Handle(msg []byte) error {
	state := &State{}
	err := json.Unmarshal(msg, state)
	if err != nil {
		return err
	}
	msgType := strings.Split(state.MsgType, "/")
	current := c.CheckState()
	state = &State{
		MsgType:      state.MsgType,
		ConnectionID: state.ConnectionID,
		ThreadID:     state.ThreadID,
		protocol:     msgType[1],
		version:      msgType[2],
		requestType:  msgType[3],
		current:      current,
	}
	c.State = state
	err = c.setState()
	if err != nil {
		return err
	}
	return nil
}

//CheckState checks the current state of didComm state
func (c *Context) CheckState() string {
	s := []string{c.State.protocol, c.State.version, c.State.ConnectionID, c.State.ThreadID["thid"]}
	compositeKey := strings.Join(s, "")
	respBytes, _ := c.Store.Get(compositeKey)

	if respBytes == nil {
		c.State.current = NullState
	} else {
		c.State.current = string(respBytes)
	}
	return c.State.current
}

func (c *Context) setState() error {
	switch c.State.requestType {
	case invitation:
		err := c.invitation()
		if err != nil {
			return err
		}
	case request:
		err := c.receive()
		if err != nil {
			return err
		}
	case response:
		err := c.send()
		if err != nil {
			return err
		}
		//TODO: Acknowledgement needs to follow RFCS-0015 for acks : https://github.com/hyperledger/aries-rfcs/tree/master/features/0015-acks
	case ack:
		err := c.complete()
		if err != nil {
			return err
		}
	default:
		c.nullState()
	}
	return nil
}

// newState creates a new State machine
func newState() *State {
	return &State{current: NullState}
}

// invitation gets triggered when the invitation msg is passed to Handle method. It transition the current State from null to Invited for INVITER
func (c *Context) invitation() error {
	if c.State.current == NullState {
		s := []string{c.State.protocol, c.State.version, c.State.ConnectionID, c.State.ThreadID["thid"]}
		compositeKey := strings.Join(s, "")
		c.State.current = InvitedState
		err := c.Store.Put(compositeKey, []byte(c.State.current))
		if err != nil {
			return err
		}
	}
	return nil
}

// receive transition the Current State from invited to requested for INVITER
func (c *Context) receive() error {
	if c.State.current == InvitedState {
		c.State.current = RequestedState
		s := []string{c.State.protocol, c.State.version, c.State.ConnectionID, c.State.ThreadID["thid"]}
		compositeKey := strings.Join(s, "")
		err := c.Store.Put(compositeKey, []byte(c.State.current))
		if err != nil {
			return err
		}
	}
	return nil
}

// send transition the Current State from requested to responded for INVITER
func (c *Context) send() error {
	if c.State.current == RequestedState {
		c.State.current = RespondedState
		s := []string{c.State.protocol, c.State.version, c.State.ConnectionID, c.State.ThreadID["thid"]}
		compositeKey := strings.Join(s, "")
		err := c.Store.Put(compositeKey, []byte(c.State.current))
		if err != nil {
			return err
		}
	}
	return nil
}

// send transition the Current State from requested to responded for INVITEE
func (c *Context) complete() error {
	if c.State.current == RespondedState {
		c.State.current = CompleteState
		s := []string{c.State.protocol, c.State.version, c.State.ConnectionID, c.State.ThreadID["thid"]}
		compositeKey := strings.Join(s, "")
		err := c.Store.Put(compositeKey, []byte(c.State.current))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Context) nullState() {
	c.State.current = NullState

}
