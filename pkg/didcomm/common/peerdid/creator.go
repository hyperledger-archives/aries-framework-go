/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peerdid

import (
	"encoding/json"
	"fmt"

	gojose "github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
)

const (
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	bls12381G2Key2020          = "Bls12381G2Key2020"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	jsonWebKey2020             = "JsonWebKey2020"
)

// Creator implements the Out-Of-Band V2 protocol.
type Creator struct {
	vdrRegistry      vdrapi.Registry
	kms              kms.KeyManager
	keyType          kms.KeyType
	keyAgreementType kms.KeyType
}

// Provider provides this service's dependencies.
type Provider interface {
	VDRegistry() vdrapi.Registry
	KMS() kms.KeyManager
	KeyType() kms.KeyType
	KeyAgreementType() kms.KeyType
}

// New creates a new instance of the out-of-band service.
func New(p Provider) *Creator {
	return &Creator{
		vdrRegistry:      p.VDRegistry(),
		kms:              p.KMS(),
		keyType:          p.KeyType(),
		keyAgreementType: p.KeyAgreementType(),
	}
}

// CreatePeerDIDV2 create a peer DID suitable for use in DIDComm V2.
func (s *Creator) CreatePeerDIDV2() (*did.Doc, error) {
	newDID := &did.Doc{Service: []did.Service{{Type: vdrapi.DIDCommV2ServiceType}}}

	err := s.createNewKeyAndVM(newDID)
	if err != nil {
		return nil, fmt.Errorf("creating new keys and VMS for DID document failed: %w", err)
	}

	// set KeyAgreement.ID as RecipientKeys as part of DIDComm V2 service
	newDID.Service[0].RecipientKeys = []string{newDID.KeyAgreement[0].VerificationMethod.ID}

	myDID, err := s.vdrRegistry.Create(peer.DIDMethod, newDID)
	if err != nil {
		return nil, fmt.Errorf("creating new peer DID via VDR failed: %w", err)
	}

	return myDID.DIDDocument, nil
}

func (s *Creator) createNewKeyAndVM(didDoc *did.Doc) error {
	vm, err := s.createSigningVM()
	if err != nil {
		return err
	}

	kaVM, err := s.createEncryptionVM()
	if err != nil {
		return err
	}

	didDoc.VerificationMethod = append(didDoc.VerificationMethod, *vm)

	didDoc.Authentication = append(didDoc.Authentication, *did.NewReferencedVerification(vm, did.Authentication))
	didDoc.KeyAgreement = append(didDoc.KeyAgreement, *did.NewReferencedVerification(kaVM, did.KeyAgreement))

	return nil
}

// nolint:gochecknoglobals
var vmTypeMap = map[kms.KeyType]string{
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
	return vmTypeMap[kt]
}

func (s *Creator) createSigningVM() (*did.VerificationMethod, error) {
	vmType := getVerMethodType(s.keyType)

	_, pubKeyBytes, err := s.kms.CreateAndExportPubKeyBytes(s.keyType)
	if err != nil {
		return nil, fmt.Errorf("createSigningVM: %w", err)
	}

	vmID := "#key-1"

	switch vmType {
	case ed25519VerificationKey2018, bls12381G2Key2020:
		return did.NewVerificationMethodFromBytes(vmID, vmType, "", pubKeyBytes), nil
	case jsonWebKey2020:
		j, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, s.keyType)
		if err != nil {
			return nil, fmt.Errorf("createSigningVM: failed to convert public key to JWK for VM: %w", err)
		}

		return did.NewVerificationMethodFromJWK(vmID, vmType, "", j)
	default:
		return nil, fmt.Errorf("createSigningVM: unsupported verification method: '%s'", vmType)
	}
}

func (s *Creator) createEncryptionVM() (*did.VerificationMethod, error) {
	encKeyType := s.keyAgreementType

	vmType := getVerMethodType(encKeyType)

	_, kaPubKeyBytes, err := s.kms.CreateAndExportPubKeyBytes(encKeyType)
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
