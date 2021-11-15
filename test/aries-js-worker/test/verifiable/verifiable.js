/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {healthCheck, newAries, newAriesREST} from "../common.js"
import {environment} from "../environment.js";

const agentControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

// verifiable credential
const vcName = "faber-college-credentials"
const didName = "alice-did"
const vcID = "http://faber.edu/credentials/1989"
const vc = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc-revocation-list-2020/v1"
  ],
  "id": "http://faber.edu/credentials/1989",
  "type": "VerifiableCredential",
  "credentialSubject": {
    "id": "did:example:iuajk1f712ebc6f1c276e12ec21"
  },
  "issuer": {
    "id": "did:example:09s12ec712ebc6f1c671ebfeb1f",
    "name": "Faber University"
  },
  "issuanceDate": "2020-01-01T10:54:01Z",
  "credentialStatus": {
    "id": "https://dmv.example.gov/credentials/status/3#94567",
    "type": "RevocationList2020Status",
    "revocationListIndex": "94567",
    "revocationListCredential": "https://example.com/credentials/status/3"
  }
}`

const restMode = 'rest'
const wasmMode = 'wasm'
const didID = `${environment.DID_ID}`



describe("Verifiable Store Test", function () {
    describe(restMode, function () {
        verifiableStore(newAriesREST(agentControllerApiUrl, [`${environment.USER_MEDIA_TYPE_PROFILES}`]), restMode)
    })
    describe(wasmMode, function () {
        verifiableStore(newAries('demo', 'demo-agent', [`${environment.HTTP_LOCAL_DID_RESOLVER}`], null, [`${environment.USER_MEDIA_TYPE_PROFILES}`]))
    })
})

async function verifiableStore(newAries, mode = wasmMode) {
    let aries
    let did
    let retries = 10;
    let modePrefix = '[' + mode + '] '

    before(async () => {
        aries = await newAries
    })

    after(async () => {
        await aries.destroy()
    })

    it(modePrefix + "Alice stores the verifiable credential received from the college", function (done) {
        aries.verifiable.validateCredential({
            "verifiableCredential": vc
        }).then(
            resp => {
                aries.verifiable.saveCredential({
                    "name": vcName,
                    "verifiableCredential": vc
                }).then(
                    resp => done(),
                    err => done(err)
                )
            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice verifies that the verifiable credential stored with correct name", function (done) {
        var id = ''
        aries.verifiable.getCredentialByName({
            "name": vcName
        }).then(
            resp => {
                id = resp.id

                try {
                    assert.equal(vcID, id)

                    aries.verifiable.getCredential({
                        "id": getID(mode, id)
                    }).then(
                        resp => done(),
                        err => done(err)
                    )
                } catch (err) {
                    done(err)
                }

            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice validates that she has only one verifiable credential", function (done) {
        aries.verifiable.getCredentials().then(
            resp => {
                let found = false;
                for (let i = 0; i < resp.result.length; i++) {
                    if (vcName === resp.result[i].name) {
                        try {
                            assert.equal(vcID, resp.result[i].id)
                            assert.equal(vcName, resp.result[i].name)
                            assert.isNotEmpty(vcName, resp.result[i].type)
                            assert.isNotEmpty(vcName, resp.result[i].context)
                            found = true;
                        } catch (err) {
                            done(err)
                        }
                    }
                }

                if (!found) {
                    done(new Error("credential: not found"))
                }

                done()
            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice makes sure that the DID is resolvable", async function () {
        let resp;
        for (let i = 0; i < retries; i++) {
            try {
                resp = await aries.vdr.resolveDID({id:getID(mode, didID)})

                break
            }catch (e) {
                if (!e.message.includes("DID does not exist")) {
                    assert.fail(e.message);
                }
                await new Promise(r => setTimeout(r, 1000));
                console.warn(e.message)
            }
        }
        did=resp.didDocument

        try {
            await aries.kms.importKey({
                kty: "OKP",
                d:"nmsQIprcP0RTwKrGE4FaT4l9UbIM1bxu03vwbZpbKOw",
                crv:"Ed25519",
                kid:"key1",
                x:"axETCKcguKigxZiJIPtgotDbVe72AIXRTbF2MRpZIk0"
            })
        }catch (e) {
            assert.fail(e.message);
        }
    })

    it(modePrefix + "Alice stores the did generated by her", function (done) {
        aries.vdr.saveDID({
            name: mode + "_" + didName,
            did: did
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice generates the signed  verifiable credential to pass it to the employer", async function () {
        await aries.verifiable.signCredential({
            "credential": JSON.parse(vc),
            "did": did.id,
            "signatureType": "JsonWebSignature2020"
        }).then(
            resp => {
                try {
                    assert.isNotEmpty(resp.verifiableCredential.proof)
                } catch (err) {
                    assert.fail(err)
                }
            }, err => assert.fail(err)
        )
    });

    it(modePrefix + "Alice generates the signed  verifiable presentation to pass it to the employer", async function () {
        await aries.verifiable.generatePresentation({
            "verifiableCredential": [JSON.parse(vc)],
            "did": did.id,
            "signatureType": "JsonWebSignature2020"
        }).then(
            resp => {
                try {
                    assert.isTrue(resp.verifiablePresentation.type.includes("VerifiablePresentation"))
                } catch (err) {
                    assert.fail(err)
                }
            }, err => assert.fail(err)
        )
    });
}

function getID(mode, id) {
    if (mode === restMode) {
        return window.btoa(id)
    }

    return id
}
