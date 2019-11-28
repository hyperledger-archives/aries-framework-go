/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"testing"
)

func TestAutoExecuteActionEvent(t *testing.T) {
	ch := make(chan DIDCommAction)
	done := make(chan struct{})

	go func() {
		AutoExecuteActionEvent(ch)
		close(done)
	}()

	ch <- DIDCommAction{Continue: func(args interface{}) {
	}}

	close(ch)
	<-done
}
