/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries} from "../common.js"

// verifiable credential
const vcName = "faber-college-credentials"
const vcID = "http://faber.edu/credentials/1989"
const vc = `
{ 
   "@context":[ 
      "https://www.w3.org/2018/credentials/v1"
   ],
   "id":"http://faber.edu/credentials/1989",
   "type":"VerifiableCredential",
   "credentialSubject":{ 
      "id":"did:example:iuajk1f712ebc6f1c276e12ec21"
   },
   "issuer":{ 
      "id":"did:example:09s12ec712ebc6f1c671ebfeb1f",
      "name":"Faber University"
   },
   "issuanceDate":"2020-01-01T10:54:01Z",
   "credentialStatus":{ 
      "id":"https://example.gov/status/65",
      "type":"CredentialStatusList2017"
   }
}`

// scenarios
describe("Verifiable Store", function () {
    let aries

    before(async () => {
        await newAries()
            .then(a => {
                aries = a
            })
            .catch(err => new Error(err.message));
    })

    after(() => {
        aries.destroy()
    })

    it("Alice stores the verifiable credential received from the college", function (done) {
        aries.verifiable.validateCredential({
            "vc": vc
        }).then(
            resp => {
                aries.verifiable.saveCredential({
                    "name": vcName,
                    "vc": vc
                }).then(
                    resp => done(),
                    err => done(err)
                )
            },
            err => done(err)
        )
    })

    it("Alice verifies that the verifiable credential stored with correct name", function (done) {
        var id = ''
        aries.verifiable.getCredentialByName({
            "name": vcName
        }).then(
            resp => {
                id = resp.id

                try {
                    assert.equal(vcID, id)

                    aries.verifiable.getCredential({
                        "id": id
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

    it("Alice validates that she has only one verifiable credential", function (done) {
        aries.verifiable.getCredentials().then(
            resp => {
                try {
                    assert.equal(1, resp.result.length)
                    assert.equal(vcID, resp.result[0].id)
                    assert.equal(vcName, resp.result[0].name)
                } catch (err) {
                    done(err)
                }

                done()
            },
            err => done(err)
        )
    })
})