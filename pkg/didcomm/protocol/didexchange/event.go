/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

// didExchangeEvent implements didexchange.Event interface.
type didExchangeEvent struct {
	connectionID string
	invitationID string
}

// ConnectionID returns DIDExchange connectionID.
func (ex *didExchangeEvent) ConnectionID() string {
	return ex.connectionID
}

// InvitationID returns DIDExchange invitationID.
func (ex *didExchangeEvent) InvitationID() string {
	return ex.invitationID
}

// All implements EventProperties interface.
func (ex *didExchangeEvent) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": ex.ConnectionID(),
		"invitationID": ex.InvitationID(),
	}
}

// didExchangeEvent for sending events with processing error.
type didExchangeEventError struct {
	didExchangeEvent
	err error
}

// Error implements error interface.
func (ex *didExchangeEventError) Error() string {
	if ex.err != nil {
		return ex.err.Error()
	}

	return ""
}

// All implements EventProperties interface.
func (ex *didExchangeEventError) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": ex.ConnectionID(),
		"invitationID": ex.InvitationID(),
		"error":        ex.Error(),
	}
}
