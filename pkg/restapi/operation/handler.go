/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/go-openapi/runtime/middleware/denco"

//Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() denco.HandlerFunc
}
