/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST} from "../common.js"
import {environment} from "../environment.js";

const agentControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'

const sampleContext = JSON.parse(`{
   "@context":{
      "name":"http://schema.org/name",
      "image":{
         "@id":"http://schema.org/image",
         "@type":"@id"
      },
      "homepage":{
         "@id":"http://schema.org/url",
         "@type":"@id"
      }
   }
}`)

describe("JSON-LD API Test", function () {
    describe(restMode, function () {
        ld(restMode)
    })
    describe(wasmMode, function () {
        ld(wasmMode)
    })
})

async function ld(mode) {
    let aries
    let modePrefix = '[' + mode + '] '

    before(async () => {
        if (mode === restMode) {
            aries = await newAriesREST(agentControllerApiUrl, [`${environment.USER_MEDIA_TYPE_PROFILES}`])
        } else {
            aries = await newAries(null, null, null, null, [`${environment.USER_MEDIA_TYPE_PROFILES}`])
        }
    })

    after(async () => {
        await aries.destroy()
    })

    it(modePrefix + "Alice imports extra JSON-LD contexts", function (done) {
        aries.ld.addContexts({
            documents: [
                {
                    url: "http://schema.org/name",
                    content: sampleContext
                }
            ]
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    let providerID;

    it(modePrefix + "Alice adds a new remote context provider", function (done) {
        let host = (mode === restMode) ? "file-server.js.example.com" : "localhost";

        aries.ld.addRemoteProvider({
            endpoint: "http://" + host + ":10096/ld-test-contexts.json"
        }).then(
            resp => {
                try {
                    assert.isNotEmpty(resp.id);
                    providerID = resp.id;
                } catch (err) {
                    done(err)
                }
                done()
            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice refreshes remote context provider", function (done) {
        aries.ld.refreshRemoteProvider({
            id: providerID
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice gets all remote context providers", function (done) {
        aries.ld.getAllRemoteProviders().then(
            resp => {
                assert.isNotEmpty(resp.providers)
                done()
            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice refreshes all remote context providers", function (done) {
        aries.ld.refreshAllRemoteProviders().then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    it(modePrefix + "Alice deletes remote context provider", function (done) {
        aries.ld.deleteRemoteProvider({
            id: providerID
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })
}
