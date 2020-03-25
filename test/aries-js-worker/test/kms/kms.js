/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST} from "../common.js"
import {environment} from "../environment.js";

const agentControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'

describe("KMS Test", async function () {
    await kms(newAriesREST(agentControllerApiUrl), restMode)
    await kms(newAries())
})

async function kms(newAries, mode = wasmMode) {
    let aries
    let modePrefix = '[' + mode + '] '

    before(async () => {
        await newAries
            .then(a => {
                aries = a
            })
            .catch(err => new Error(err.message));
    })

    after(() => {
        aries.destroy()
    })

    it(modePrefix + "Alice create key set", function (done) {
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
