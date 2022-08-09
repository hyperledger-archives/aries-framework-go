/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

// connectionEvent implements connection.Event interface.
type connectionEvent struct {
	connectionID string
	invitationID string
}

// ConnectionID returns Connection connectionID.
func (ex *connectionEvent) ConnectionID() string {
	return ex.connectionID
}

// InvitationID returns Connection invitationID.
func (ex *connectionEvent) InvitationID() string {
	return ex.invitationID
}

// connectionEventError for sending events with processing error.
type connectionEventError struct {
	connectionEvent
	err error
}

// Error implements error interface.
func (ex *connectionEventError) Error() string {
	if ex.err != nil {
		return ex.err.Error()
	}

	return ""
}

// All implements EventProperties interface.
func (ex *connectionEvent) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": ex.ConnectionID(),
		"invitationID": ex.InvitationID(),
	}
}

// All implements EventProperties interface.
func (ex *connectionEventError) All() map[string]interface{} {
	return map[string]interface{}{
		"connectionID": ex.ConnectionID(),
		"invitationID": ex.InvitationID(),
		"error":        ex.Error(),
	}
}
