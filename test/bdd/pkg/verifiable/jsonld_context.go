/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

const vcContext = `

{
  "@context": {
    "@version": 1.1,
    "@protected": true,

    "id": "@id",
    "type": "@type",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "credentialSchema": {
          "@id": "cred:credentialSchema",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "JsonSchemaValidator2018": "cred:JsonSchemaValidator2018"
          }
        },
        "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
        "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
        "evidence": {"@id": "cred:evidence", "@type": "@id"},
        "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "refreshService": {
          "@id": "cred:refreshService",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "ManualRefreshService2018": "cred:ManualRefreshService2018"
          }
        },
        "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
        "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
        "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
      }
    },

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",

        "holder": {"@id": "cred:holder", "@type": "@id"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "verifiableCredential": {"@id": "cred:verifiableCredential", "@type": "@id", "@container": "@graph"}
      }
    },

    "EcdsaSecp256k1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "EcdsaSecp256r1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "Ed25519Signature2018": {
      "@id": "https://w3id.org/security#Ed25519Signature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "RsaSignature2018": {
      "@id": "https://w3id.org/security#RsaSignature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "proof": {"@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph"}
  }
}
`

const vcExampleContext = `
{
  "@context": [{
    "@version": 1.1
  },"https://www.w3.org/ns/odrl.jsonld", {
    "ex": "https://example.org/examples#",
    "schema": "http://schema.org/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",

    "3rdPartyCorrelation": "ex:3rdPartyCorrelation",
    "AllVerifiers": "ex:AllVerifiers",
    "Archival": "ex:Archival",
    "BachelorDegree": "ex:BachelorDegree",
    "Child": "ex:Child",
    "CLCredentialDefinition2019": "ex:CLCredentialDefinition2019",
    "CLSignature2019": "ex:CLSignature2019",
    "IssuerPolicy": "ex:IssuerPolicy",
    "HolderPolicy": "ex:HolderPolicy",
    "Mother": "ex:Mother",
    "RelationshipCredential": "ex:RelationshipCredential",
    "UniversityDegreeCredential": "ex:UniversityDegreeCredential",
    "ZkpExampleSchema2018": "ex:ZkpExampleSchema2018",

    "issuerData": "ex:issuerData",
    "attributes": "ex:attributes",
    "signature": "ex:signature",
    "signatureCorrectnessProof": "ex:signatureCorrectnessProof",
    "primaryProof": "ex:primaryProof",
    "nonRevocationProof": "ex:nonRevocationProof",

    "alumniOf": {"@id": "schema:alumniOf", "@type": "rdf:HTML"},
    "child": {"@id": "ex:child", "@type": "@id"},
    "degree": "ex:degree",
    "degreeType": "ex:degreeType",
    "degreeSchool": "ex:degreeSchool",
    "college": "ex:college",
    "name": {"@id": "schema:name", "@type": "rdf:HTML"},
    "givenName": "schema:givenName",
    "familyName": "schema:familyName",
    "parent": {"@id": "ex:parent", "@type": "@id"},
    "referenceId": "ex:referenceId",
    "documentPresence": "ex:documentPresence",
    "evidenceDocument": "ex:evidenceDocument",
    "spouse": "schema:spouse",
    "subjectPresence": "ex:subjectPresence",
    "verifier": {"@id": "ex:verifier", "@type": "@id"}
  }]
}
`

const odrlContext = `
{
 "@context": {
    "odrl":    "http://www.w3.org/ns/odrl/2/",
    "rdf":     "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs":    "http://www.w3.org/2000/01/rdf-schema#",
    "owl":     "http://www.w3.org/2002/07/owl#",
    "skos":    "http://www.w3.org/2004/02/skos/core#",
    "dct":     "http://purl.org/dc/terms/",
    "xsd":     "http://www.w3.org/2001/XMLSchema#",
    "vcard":   "http://www.w3.org/2006/vcard/ns#",
    "foaf":    "http://xmlns.com/foaf/0.1/",
    "schema":  "http://schema.org/",
    "cc":      "http://creativecommons.org/ns#",

    "uid":     "@id",
    "type":    "@type",

    "Policy":           "odrl:Policy",
    "Rule":             "odrl:Rule",
    "profile":          {"@type": "@id", "@id": "odrl:profile"},

    "inheritFrom":      {"@type": "@id", "@id": "odrl:inheritFrom"},

    "ConflictTerm":     "odrl:ConflictTerm",
    "conflict":         {"@type": "@vocab", "@id": "odrl:conflict"},
    "perm":             "odrl:perm",
    "prohibit":         "odrl:prohibit",
    "invalid":          "odrl:invalid",

    "Agreement":           "odrl:Agreement",
    "Assertion":           "odrl:Assertion",
    "Offer":               "odrl:Offer",
    "Privacy":             "odrl:Privacy",
    "Invitation":             "odrl:Invitation",
    "Set":                 "odrl:Set",
    "Ticket":              "odrl:Ticket",

    "Asset":               "odrl:Asset",
    "AssetCollection":     "odrl:AssetCollection",
    "relation":            {"@type": "@id", "@id": "odrl:relation"},
    "hasPolicy":           {"@type": "@id", "@id": "odrl:hasPolicy"},

    "target":             {"@type": "@id", "@id": "odrl:target"},
    "output":             {"@type": "@id", "@id": "odrl:output"},

    "partOf":            {"@type": "@id", "@id": "odrl:partOf"},
	"source":            {"@type": "@id", "@id": "odrl:source"},

    "Party":              "odrl:Party",
    "PartyCollection":    "odrl:PartyCollection",
    "function":           {"@type": "@vocab", "@id": "odrl:function"},
    "PartyScope":         "odrl:PartyScope",

    "assignee":             {"@type": "@id", "@id": "odrl:assignee"},
    "assigner":             {"@type": "@id", "@id": "odrl:assigner"},
	"assigneeOf":           {"@type": "@id", "@id": "odrl:assigneeOf"},
    "assignerOf":           {"@type": "@id", "@id": "odrl:assignerOf"},
    "attributedParty":      {"@type": "@id", "@id": "odrl:attributedParty"},
	"attributingParty":     {"@type": "@id", "@id": "odrl:attributingParty"},
    "compensatedParty":     {"@type": "@id", "@id": "odrl:compensatedParty"},
    "compensatingParty":    {"@type": "@id", "@id": "odrl:compensatingParty"},
    "consentingParty":      {"@type": "@id", "@id": "odrl:consentingParty"},
	"consentedParty":       {"@type": "@id", "@id": "odrl:consentedParty"},
    "informedParty":        {"@type": "@id", "@id": "odrl:informedParty"},
	"informingParty":       {"@type": "@id", "@id": "odrl:informingParty"},
    "trackingParty":        {"@type": "@id", "@id": "odrl:trackingParty"},
	"trackedParty":         {"@type": "@id", "@id": "odrl:trackedParty"},
	"contractingParty":     {"@type": "@id", "@id": "odrl:contractingParty"},
	"contractedParty":      {"@type": "@id", "@id": "odrl:contractedParty"},

    "Action":                "odrl:Action",
    "action":                {"@type": "@vocab", "@id": "odrl:action"},
    "includedIn":            {"@type": "@id", "@id": "odrl:includedIn"},
    "implies":               {"@type": "@id", "@id": "odrl:implies"},

    "Permission":            "odrl:Permission",
    "permission":            {"@type": "@id", "@id": "odrl:permission"},

    "Prohibition":           "odrl:Prohibition",
    "prohibition":           {"@type": "@id", "@id": "odrl:prohibition"},

    "obligation":            {"@type": "@id", "@id": "odrl:obligation"},

    "use":                   "odrl:use",
    "grantUse":              "odrl:grantUse",
    "aggregate":             "odrl:aggregate",
    "annotate":              "odrl:annotate",
    "anonymize":             "odrl:anonymize",
    "archive":               "odrl:archive",
    "concurrentUse":         "odrl:concurrentUse",
    "derive":                "odrl:derive",
    "digitize":              "odrl:digitize",
    "display":               "odrl:display",
    "distribute":            "odrl:distribute",
    "execute":               "odrl:execute",
    "extract":               "odrl:extract",
    "give":                  "odrl:give",
    "index":                 "odrl:index",
    "install":               "odrl:install",
    "modify":                "odrl:modify",
    "move":                  "odrl:move",
    "play":                  "odrl:play",
    "present":               "odrl:present",
    "print":                 "odrl:print",
    "read":                  "odrl:read",
    "reproduce":             "odrl:reproduce",
    "sell":                  "odrl:sell",
    "stream":                "odrl:stream",
    "textToSpeech":          "odrl:textToSpeech",
    "transfer":              "odrl:transfer",
    "transform":             "odrl:transform",
    "translate":             "odrl:translate",

    "Duty":                 "odrl:Duty",
    "duty":                 {"@type": "@id", "@id": "odrl:duty"},
    "consequence":          {"@type": "@id", "@id": "odrl:consequence"},
	"remedy":               {"@type": "@id", "@id": "odrl:remedy"},

    "acceptTracking":       "odrl:acceptTracking",
    "attribute":            "odrl:attribute",
    "compensate":           "odrl:compensate",
    "delete":               "odrl:delete",
    "ensureExclusivity":    "odrl:ensureExclusivity",
    "include":              "odrl:include",
    "inform":               "odrl:inform",
    "nextPolicy":           "odrl:nextPolicy",
    "obtainConsent":        "odrl:obtainConsent",
    "reviewPolicy":         "odrl:reviewPolicy",
    "uninstall":            "odrl:uninstall",
    "watermark":            "odrl:watermark",

    "Constraint":           "odrl:Constraint",
	"LogicalConstraint":    "odrl:LogicalConstraint",
    "constraint":           {"@type": "@id", "@id": "odrl:constraint"},
	"refinement":           {"@type": "@id", "@id": "odrl:refinement"},
    "Operator":             "odrl:Operator",
    "operator":             {"@type": "@vocab", "@id": "odrl:operator"},
    "RightOperand":         "odrl:RightOperand",
    "rightOperand":         "odrl:rightOperand",
    "rightOperandReference":{"@type": "xsd:anyURI", "@id": "odrl:rightOperandReference"},
    "LeftOperand":          "odrl:LeftOperand",
    "leftOperand":          {"@type": "@vocab", "@id": "odrl:leftOperand"},
    "unit":                 "odrl:unit",
    "dataType":             {"@type": "xsd:anyType", "@id": "odrl:datatype"},
    "status":               "odrl:status",

    "absolutePosition":        "odrl:absolutePosition",
    "absoluteSpatialPosition": "odrl:absoluteSpatialPosition",
    "absoluteTemporalPosition":"odrl:absoluteTemporalPosition",
    "absoluteSize":            "odrl:absoluteSize",
    "count":                   "odrl:count",
    "dateTime":                "odrl:dateTime",
    "delayPeriod":             "odrl:delayPeriod",
    "deliveryChannel":         "odrl:deliveryChannel",
    "elapsedTime":             "odrl:elapsedTime",
    "event":                   "odrl:event",
    "fileFormat":              "odrl:fileFormat",
    "industry":                "odrl:industry:",
    "language":                "odrl:language",
    "media":                   "odrl:media",
    "meteredTime":             "odrl:meteredTime",
    "payAmount":               "odrl:payAmount",
    "percentage":              "odrl:percentage",
    "product":                 "odrl:product",
    "purpose":                 "odrl:purpose",
    "recipient":               "odrl:recipient",
    "relativePosition":        "odrl:relativePosition",
    "relativeSpatialPosition": "odrl:relativeSpatialPosition",
    "relativeTemporalPosition":"odrl:relativeTemporalPosition",
    "relativeSize":            "odrl:relativeSize",
    "resolution":              "odrl:resolution",
    "spatial":                 "odrl:spatial",
    "spatialCoordinates":      "odrl:spatialCoordinates",
    "systemDevice":            "odrl:systemDevice",
    "timeInterval":            "odrl:timeInterval",
    "unitOfCount":             "odrl:unitOfCount",
    "version":                 "odrl:version",
    "virtualLocation":         "odrl:virtualLocation",

    "eq":                   "odrl:eq",
    "gt":                   "odrl:gt",
    "gteq":                 "odrl:gteq",
    "lt":                   "odrl:lt",
    "lteq":                 "odrl:lteq",
    "neq":                  "odrl:neg",
    "isA":                  "odrl:isA",
    "hasPart":              "odrl:hasPart",
    "isPartOf":             "odrl:isPartOf",
    "isAllOf":              "odrl:isAllOf",
    "isAnyOf":              "odrl:isAnyOf",
    "isNoneOf":             "odrl:isNoneOf",
    "or":                   "odrl:or",
    "xone":                 "odrl:xone",
    "and":                  "odrl:and",
    "andSequence":          "odrl:andSequence",

    "policyUsage":                "odrl:policyUsage"

    }
}
`

const trustblocContext = `
{
  "@context": {
    "@version": 1.1,

    "id": "@id",
    "type": "@type",

    "trustbloc": "https://trustbloc.github.io/context#",
    "ldssk": "https://w3c-ccg.github.io/lds-jws2020/contexts/#",
    "sec": "https://w3id.org/security#",

    "publicKeyJwk": {
      "@id": "sec:publicKeyJwk",
      "@type": "@json"
    },

    "JsonWebSignature2020": {
      "@id": "https://w3c-ccg.github.io/lds-jws2020/contexts/#JsonWebSignature2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    }
  }
}
`

const securityV1Context = `
{
  "@context": {
    "id": "@id",
    "type": "@type",

    "dc": "http://purl.org/dc/terms/",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "EcdsaKoblitzSignature2016": "sec:EcdsaKoblitzSignature2016",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "EncryptedMessage": "sec:EncryptedMessage",
    "GraphSignature2012": "sec:GraphSignature2012",
    "LinkedDataSignature2015": "sec:LinkedDataSignature2015",
    "LinkedDataSignature2016": "sec:LinkedDataSignature2016",
    "CryptographicKey": "sec:Key",

    "authenticationTag": "sec:authenticationTag",
    "canonicalizationAlgorithm": "sec:canonicalizationAlgorithm",
    "cipherAlgorithm": "sec:cipherAlgorithm",
    "cipherData": "sec:cipherData",
    "cipherKey": "sec:cipherKey",
    "created": {"@id": "dc:created", "@type": "xsd:dateTime"},
    "creator": {"@id": "dc:creator", "@type": "@id"},
    "digestAlgorithm": "sec:digestAlgorithm",
    "digestValue": "sec:digestValue",
    "domain": "sec:domain",
    "encryptionKey": "sec:encryptionKey",
    "expiration": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
    "initializationVector": "sec:initializationVector",
    "iterationCount": "sec:iterationCount",
    "nonce": "sec:nonce",
    "normalizationAlgorithm": "sec:normalizationAlgorithm",
    "owner": {"@id": "sec:owner", "@type": "@id"},
    "password": "sec:password",
    "privateKey": {"@id": "sec:privateKey", "@type": "@id"},
    "privateKeyPem": "sec:privateKeyPem",
    "publicKey": {"@id": "sec:publicKey", "@type": "@id"},
    "publicKeyBase58": "sec:publicKeyBase58",
    "publicKeyPem": "sec:publicKeyPem",
    "publicKeyWif": "sec:publicKeyWif",
    "publicKeyService": {"@id": "sec:publicKeyService", "@type": "@id"},
    "revoked": {"@id": "sec:revoked", "@type": "xsd:dateTime"},
    "salt": "sec:salt",
    "signature": "sec:signature",
    "signatureAlgorithm": "sec:signingAlgorithm",
    "signatureValue": "sec:signatureValue"
  }
}
`

const securityV2Context = `
{
  "@context": [{
    "@version": 1.1
  }, "https://w3id.org/security/v1", {
    "AesKeyWrappingKey2019": "sec:AesKeyWrappingKey2019",
    "DeleteKeyOperation": "sec:DeleteKeyOperation",
    "DeriveSecretOperation": "sec:DeriveSecretOperation",
    "EcdsaSecp256k1Signature2019": "sec:EcdsaSecp256k1Signature2019",
    "EcdsaSecp256r1Signature2019": "sec:EcdsaSecp256r1Signature2019",
    "EcdsaSecp256k1VerificationKey2019": "sec:EcdsaSecp256k1VerificationKey2019",
    "EcdsaSecp256r1VerificationKey2019": "sec:EcdsaSecp256r1VerificationKey2019",
    "Ed25519Signature2018": "sec:Ed25519Signature2018",
    "Ed25519VerificationKey2018": "sec:Ed25519VerificationKey2018",
    "EquihashProof2018": "sec:EquihashProof2018",
    "ExportKeyOperation": "sec:ExportKeyOperation",
    "GenerateKeyOperation": "sec:GenerateKeyOperation",
    "KmsOperation": "sec:KmsOperation",
    "RevokeKeyOperation": "sec:RevokeKeyOperation",
    "RsaSignature2018": "sec:RsaSignature2018",
    "RsaVerificationKey2018": "sec:RsaVerificationKey2018",
    "Sha256HmacKey2019": "sec:Sha256HmacKey2019",
    "SignOperation": "sec:SignOperation",
    "UnwrapKeyOperation": "sec:UnwrapKeyOperation",
    "VerifyOperation": "sec:VerifyOperation",
    "WrapKeyOperation": "sec:WrapKeyOperation",
    "X25519KeyAgreementKey2019": "sec:X25519KeyAgreementKey2019",

    "allowedAction": "sec:allowedAction",
    "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
    "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"},
    "capability": {"@id": "sec:capability", "@type": "@id"},
    "capabilityAction": "sec:capabilityAction",
    "capabilityChain": {"@id": "sec:capabilityChain", "@type": "@id", "@container": "@list"},
    "capabilityDelegation": {"@id": "sec:capabilityDelegationMethod", "@type": "@id", "@container": "@set"},
    "capabilityInvocation": {"@id": "sec:capabilityInvocationMethod", "@type": "@id", "@container": "@set"},
    "caveat": {"@id": "sec:caveat", "@type": "@id", "@container": "@set"},
    "challenge": "sec:challenge",
    "ciphertext": "sec:ciphertext",
    "controller": {"@id": "sec:controller", "@type": "@id"},
    "delegator": {"@id": "sec:delegator", "@type": "@id"},
    "equihashParameterK": {"@id": "sec:equihashParameterK", "@type": "xsd:integer"},
    "equihashParameterN": {"@id": "sec:equihashParameterN", "@type": "xsd:integer"},
    "invocationTarget": {"@id": "sec:invocationTarget", "@type": "@id"},
    "invoker": {"@id": "sec:invoker", "@type": "@id"},
    "jws": "sec:jws",
    "keyAgreement": {"@id": "sec:keyAgreementMethod", "@type": "@id", "@container": "@set"},
    "kmsModule": {"@id": "sec:kmsModule"},
    "parentCapability": {"@id": "sec:parentCapability", "@type": "@id"},
    "plaintext": "sec:plaintext",
    "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
    "proofPurpose": {"@id": "sec:proofPurpose", "@type": "@vocab"},
    "proofValue": "sec:proofValue",
    "referenceId": "sec:referenceId",
    "unwrappedKey": "sec:unwrappedKey",
    "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"},
    "verifyData": "sec:verifyData",
    "wrappedKey": "sec:wrappedKey"
  }]
}
`
