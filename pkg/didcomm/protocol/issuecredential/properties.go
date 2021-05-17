/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import "errors"

const (
	myDIDPropKey    = "myDID"
	theirDIDPropKey = "theirDID"
	piidPropKey     = "piid"
	errorPropKey    = "error"
)

type eventProps struct {
	properties map[string]interface{}
	myDID      string
	theirDID   string
	piid       string
	err        error
}

func newEventProps(md *MetaData) *eventProps {
	properties := md.properties
	if properties == nil {
		properties = map[string]interface{}{}
	}

	return &eventProps{
		properties: properties,
		myDID:      md.MyDID,
		theirDID:   md.TheirDID,
		piid:       md.PIID,
		err:        md.err,
	}
}

func (e *eventProps) MyDID() string {
	return e.myDID
}

func (e *eventProps) TheirDID() string {
	return e.theirDID
}

func (e *eventProps) PIID() string {
	return e.piid
}

func (e eventProps) Err() error {
	if errors.As(e.err, &customError{}) {
		return nil
	}

	return e.err
}

// All implements EventProperties interface.
func (e eventProps) All() map[string]interface{} {
	if e.myDID != "" {
		e.properties[myDIDPropKey] = e.myDID
	}

	if e.theirDID != "" {
		e.properties[theirDIDPropKey] = e.theirDID
	}

	if e.piid != "" {
		e.properties[piidPropKey] = e.piid
	}

	if e.Err() != nil {
		e.properties[errorPropKey] = e.Err()
	}

	return e.properties
}
