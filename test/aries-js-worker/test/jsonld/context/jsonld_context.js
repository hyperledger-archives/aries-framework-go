/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST} from "../../common.js"
import {environment} from "../../environment.js";
import {credentialExamplesVocab, odrlVocab} from "../../contexts.js"

const agentControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'

describe("JSON-LD Context API Test", function () {
    describe(restMode, function () {
        addContext(restMode)
    })
    describe(wasmMode, function () {
        addContext(wasmMode)
    })
})

async function addContext(mode) {
    let aries
    let modePrefix = '[' + mode + '] '

    before(async () => {
        if (mode === restMode) {
            aries = await newAriesREST(agentControllerApiUrl)
        } else {
            aries = await newAries()
        }
    })

    after(async () => {
        await aries.destroy()
    })

    it(modePrefix + "Alice imports extra JSON-LD contexts", function (done) {
        aries.context.add({
            documents: [
                {
                    url: "https://www.w3.org/2018/credentials/examples/v1",
                    content: credentialExamplesVocab
                },
                {
                    url: "https://www.w3.org/ns/odrl.jsonld",
                    content: odrlVocab
                }
            ]
        }).then(
            resp => {
                try {
                    console.log(resp);
                } catch (err) {
                    done(err)
                }
                done()
            },
            err => done(err)
        )
    })
}
