/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/json"
	"encoding/pem"
	"time"

	"encoding/hex"

	"github.com/btcsuite/btcutil/base58"
	"github.com/pkg/errors"
)

const (
	jsonldType         = "type"
	jsonldID           = "id"
	jsonldServicePoint = "serviceEndpoint"
	jsonldController   = "controller"

	// various public key encodings
	jsonldPublicKeyBase58 = "publicKeyBase58"
	jsonldPublicKeyHex    = "publicKeyHex"
	jsonldPublicKeyPem    = "publicKeyPem"
)

// Doc DID Document definition
type Doc struct {
	Context        []string
	ID             string
	PublicKey      []PublicKey
	Service        []Service
	Authentication []VerificationMethod
	Created        time.Time
	Updated        time.Time
	Proof          Proof
}

// PublicKey DID doc public key
type PublicKey struct {
	ID         string
	Type       string
	Controller string
	Value      []byte
}

// Service DID doc service
type Service struct {
	ID              string
	Type            string
	ServiceEndpoint string
	Properties      map[string]interface{}
}

// VerificationMethod authentication verification method
type VerificationMethod struct {
	PublicKey PublicKey
}

type rawDoc struct {
	Context        []string                 `json:"@context,omitempty"`
	ID             string                   `json:"id,omitempty"`
	PublicKey      []map[string]interface{} `json:"publicKey,omitempty"`
	Service        []map[string]interface{} `json:"service,omitempty"`
	Authentication []interface{}            `json:"authentication,omitempty"`
	Created        time.Time                `json:"created,omitempty"`
	Updated        time.Time                `json:"updated,omitempty"`
	Proof          Proof                    `json:"proof,omitempty"`
}

// Proof is cryptographic proof of the integrity of the DID Document
type Proof struct {
	Type           string    `json:"type,omitempty"`
	Created        time.Time `json:"created,omitempty"`
	Creator        string    `json:"creator,omitempty"`
	SignatureValue string    `json:"signatureValue,omitempty"`
	Domain         string    `json:"domain,omitempty"`
	Nonce          string    `json:"nonce,omitempty"`
}

// FromBytes creates an instance of DIDDocument by reading a JSON document from bytes
func FromBytes(data []byte) (*Doc, error) {
	// validate did document
	if err := validate(data); err != nil {
		return nil, err
	}

	raw := &rawDoc{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal did doc bytes")
	}

	publicKeys, err := populatePublicKeys(raw.PublicKey)
	if err != nil {
		return nil, errors.WithMessage(err, "populate public keys failed")
	}
	authPKs, err := populateAuthentications(raw.Authentication, publicKeys)
	if err != nil {
		return nil, errors.WithMessage(err, "populate authentications failed")
	}

	return &Doc{Context: raw.Context, ID: raw.ID, PublicKey: publicKeys, Service: populateServices(raw.Service), Authentication: authPKs,
		Created: raw.Created, Updated: raw.Updated, Proof: raw.Proof}, nil
}

func populateServices(rawServices []map[string]interface{}) []Service {
	var services []Service
	for _, rawService := range rawServices {
		service := Service{ID: stringEntry(rawService[jsonldID]), Type: stringEntry(rawService[jsonldType]),
			ServiceEndpoint: stringEntry(rawService[jsonldServicePoint])}
		delete(rawService, jsonldID)
		delete(rawService, jsonldType)
		delete(rawService, jsonldServicePoint)
		service.Properties = rawService
		services = append(services, service)
	}
	return services
}

func populateAuthentications(rawAuthentications []interface{}, pks []PublicKey) ([]VerificationMethod, error) {
	var vms []VerificationMethod
	for _, rawAuthentication := range rawAuthentications {
		valueString, ok := rawAuthentication.(string)
		if ok {
			keyExist := false
			for _, pk := range pks {
				if pk.ID == valueString {
					vms = append(vms, VerificationMethod{pk})
					keyExist = true
					break
				}
			}
			if !keyExist {
				return nil, errors.Errorf("authentication key %s not exist in did doc public key", valueString)
			}
			continue
		}

		valuePK, ok := rawAuthentication.(map[string]interface{})
		if !ok {
			return nil, errors.New("authentication value is not map[string]interface{}")
		}
		pk, err := populatePublicKeys([]map[string]interface{}{valuePK})
		if err != nil {
			return nil, err
		}
		vms = append(vms, VerificationMethod{pk[0]})

	}
	return vms, nil

}

func populatePublicKeys(rawPKs []map[string]interface{}) ([]PublicKey, error) {
	var publicKeys []PublicKey
	for _, rawPK := range rawPKs {
		decodeValue, err := decodePK(rawPK)
		if err != nil {
			return nil, err
		}
		publicKeys = append(publicKeys, PublicKey{ID: stringEntry(rawPK[jsonldID]), Type: stringEntry(rawPK[jsonldType]),
			Controller: stringEntry(rawPK[jsonldController]), Value: decodeValue})

	}
	return publicKeys, nil
}

func decodePK(rawPK map[string]interface{}) ([]byte, error) {
	if stringEntry(rawPK[jsonldPublicKeyBase58]) != "" {
		return base58.Decode(stringEntry(rawPK[jsonldPublicKeyBase58])), nil
	}
	if stringEntry(rawPK[jsonldPublicKeyHex]) != "" {
		value, err := hex.DecodeString(stringEntry(rawPK[jsonldPublicKeyHex]))
		if err != nil {
			return nil, errors.Wrapf(err, "decode public key hex failed")
		}
		return value, nil
	}
	if stringEntry(rawPK[jsonldPublicKeyPem]) != "" {
		block, _ := pem.Decode([]byte(stringEntry(rawPK[jsonldPublicKeyPem])))
		if block == nil {
			return nil, errors.New("failed to decode PEM block containing public key")
		}
		return block.Bytes, nil
	}

	return nil, errors.New("public key encoding not supported")

}

// validate did doc
func validate(doc []byte) error {
	// TODO Validate that the output DID Document conforms to the serialization of the DID Document data model (https://w3c-ccg.github.io/did-spec/#did-documents)
	return nil
}

// stringEntry
func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}
	return entry.(string)
}
