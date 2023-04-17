/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/bbs"
)

// BLS12381G2KeyTemplate creates a Tink key template for BBS+ on BLS12-381 curve with G2 group.
func BLS12381G2KeyTemplate() *tinkpb.KeyTemplate {
	return bbs.BLS12381G2KeyTemplate()
}
