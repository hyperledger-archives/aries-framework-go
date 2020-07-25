/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package introduce

import "errors"

const (
	myDIDPropKey    = "myDID"
	theirDIDPropKey = "theirDID"
	piidPropKey     = "piid"
	errorPropKey    = "error"
)

type eventProps struct {
	myDID    string
	theirDID string
	piid     string
	err      error
}

func newEventProps(md *metaData) *eventProps {
	return &eventProps{
		myDID:    md.MyDID,
		theirDID: md.TheirDID,
		piid:     md.PIID,
		err:      md.err,
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
	all := map[string]interface{}{}
	if e.myDID != "" {
		all[myDIDPropKey] = e.myDID
	}

	if e.theirDID != "" {
		all[theirDIDPropKey] = e.theirDID
	}

	if e.piid != "" {
		all[piidPropKey] = e.piid
	}

	if e.Err() != nil {
		all[errorPropKey] = e.Err()
	}

	return all
}
