/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"encoding/json"
	"fmt"

	gojose "github.com/go-jose/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
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
	case ed25519VerificationKey2018, bls12381G2Key2020:
		return did.NewVerificationMethodFromBytes(vmID, vmType, "", pubKeyBytes), nil
	case jsonWebKey2020:
		j, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, ctx.keyType)
		if err != nil {
			return nil, fmt.Errorf("createSigningVM: failed to convert public key to JWK for VM: %w", err)
		}

		return did.NewVerificationMethodFromJWK(vmID, vmType, "", j)
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
	case jsonWebKey2020:
		j, err := buildJWKFromBytes(kaPubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("createEncryptionVM: %w", err)
		}

		vm, err := did.NewVerificationMethodFromJWK(vmID, vmType, "", j)
		if err != nil {
			return nil, fmt.Errorf("createEncryptionVM: %w", err)
		}

		return vm, nil
	default:
		return nil, fmt.Errorf("unsupported verification method for KeyAgreement: '%s'", vmType)
	}
}

func buildJWKFromBytes(pubKeyBytes []byte) (*jwk.JWK, error) {
	pubKey := &crypto.PublicKey{}

	err := json.Unmarshal(pubKeyBytes, pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK for KeyAgreement: %w", err)
	}

	var j *jwk.JWK

	switch pubKey.Type {
	case "EC":
		ecKey, err := crypto.ToECKey(pubKey)
		if err != nil {
			return nil, err
		}

		j = &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key:   ecKey,
				KeyID: pubKey.KID,
			},
			Kty: pubKey.Type,
			Crv: pubKey.Curve,
		}
	case "OKP":
		j = &jwk.JWK{
			JSONWebKey: gojose.JSONWebKey{
				Key:   pubKey.X,
				KeyID: pubKey.KID,
			},
			Kty: pubKey.Type,
			Crv: pubKey.Curve,
		}
	}

	return j, nil
}

// nolint:gochecknoglobals
var vmType = map[kms.KeyType]string{
	kms.ED25519Type:            ed25519VerificationKey2018,
	kms.BLS12381G2Type:         bls12381G2Key2020,
	kms.ECDSAP256TypeDER:       jsonWebKey2020,
	kms.ECDSAP256TypeIEEEP1363: jsonWebKey2020,
	kms.ECDSAP384TypeDER:       jsonWebKey2020,
	kms.ECDSAP384TypeIEEEP1363: jsonWebKey2020,
	kms.ECDSAP521TypeDER:       jsonWebKey2020,
	kms.ECDSAP521TypeIEEEP1363: jsonWebKey2020,
	kms.X25519ECDHKWType:       x25519KeyAgreementKey2019,
	kms.NISTP256ECDHKWType:     jsonWebKey2020,
	kms.NISTP384ECDHKWType:     jsonWebKey2020,
	kms.NISTP521ECDHKWType:     jsonWebKey2020,
}

func getVerMethodType(kt kms.KeyType) string {
	return vmType[kt]
}
