/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacyconnection

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func (ctx *context) createNewKeyAndVM(didDoc *did.Doc) error {
	vm, err := ctx.createSigningVM()
	if err != nil {
		return err
	}

	kaVM, err := ctx.createEncryptionVM()
	if err != nil {
		return err
	}

	didDoc.VerificationMethod = append(didDoc.VerificationMethod, *vm)
	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.KeyAgreement = append(didDoc.KeyAgreement, *did.NewReferencedVerification(kaVM, did.KeyAgreement))

	return nil
}

func (ctx *context) createSigningVM() (*did.VerificationMethod, error) {
	vmType := getVerMethodType(ctx.keyType)

	_, pubKeyBytes, err := ctx.kms.CreateAndExportPubKeyBytes(ctx.keyType)
	if err != nil {
		return nil, fmt.Errorf("createSigningVM: %w", err)
	}

	vmID := "#key-1"

	switch vmType {
	case ed25519VerificationKey2018:
		return did.NewVerificationMethodFromBytes(vmID, vmType, "", pubKeyBytes), nil
	default:
		return nil, fmt.Errorf("createSigningVM: unsupported verification method: '%s'", vmType)
	}
}

func (ctx *context) createEncryptionVM() (*did.VerificationMethod, error) {
	encKeyType := ctx.keyAgreementType

	vmType := getVerMethodType(encKeyType)

	_, kaPubKeyBytes, err := ctx.kms.CreateAndExportPubKeyBytes(encKeyType)
	if err != nil {
		return nil, fmt.Errorf("createEncryptionVM: %w", err)
	}

	vmID := "#key-2"

	switch vmType {
	case x25519KeyAgreementKey2019:
		key := &crypto.PublicKey{}

		err = json.Unmarshal(kaPubKeyBytes, key)
		if err != nil {
			return nil, fmt.Errorf("createEncryptionVM: unable to unmarshal X25519 key: %w", err)
		}

		return did.NewVerificationMethodFromBytes(vmID, vmType, "", key.X), nil
	default:
		return nil, fmt.Errorf("unsupported verification method for KeyAgreement: '%s'", vmType)
	}
}

// nolint:gochecknoglobals
var vmType = map[kms.KeyType]string{
	kms.ED25519Type:      ed25519VerificationKey2018,
	kms.X25519ECDHKWType: x25519KeyAgreementKey2019,
}

func getVerMethodType(kt kms.KeyType) string {
	return vmType[kt]
}
