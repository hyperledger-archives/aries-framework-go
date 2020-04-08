/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST} from "../common.js"
import {environment} from "../environment.js";

const agentControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'

describe("KMS Test", function () {
    describe(restMode, function () {  kms(restMode) })
    describe(wasmMode, function () {  kms(wasmMode) })
})

async function kms(mode) {
    let aries

    before(() => {
        return new Promise((resolve, reject) => {
            let _aries;
            if (mode === restMode){
                _aries =  newAriesREST(agentControllerApiUrl)
            }else {
                _aries =   newAries()
            }

            _aries.then(
                a => {aries = a; resolve()},
                err => reject(new Error(err.message))
            )
        })
    })

    after(() => {
        aries.destroy()
    })

    it("Alice create key set", function (done) {
        aries.kms.createKeySet().then(
            resp => {
                try {
                    assert.isNotEmpty(resp.encryptionPublicKey)
                    assert.isNotEmpty(resp.signaturePublicKey)
                } catch (err) {
                    done(err)
                }
                done()
            },
            err => done(err)
        )
    })
}
