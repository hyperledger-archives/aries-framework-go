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

    before(async () => {
        if (mode === restMode){
            aries = await newAriesREST(agentControllerApiUrl, [`${environment.USER_MEDIA_TYPE_PROFILES}`])
        }else {
            aries = await newAries(null, null, null, null, [`${environment.USER_MEDIA_TYPE_PROFILES}`])
        }
    })

    after(async () => {
        await aries.destroy()
    })

    it("Alice create key set", function (done) {
        aries.kms.createKeySet({
            keyType: "ED25519"
        }).then(
            resp => {
                try {
                    assert.isNotEmpty(resp.keyID)
                    assert.isNotEmpty(resp.publicKey)
                } catch (err) {
                    done(err)
                }
                done()
            },
            err => done(err)
        )
    })

    it("Alice import ed25519 key", function (done) {
        aries.kms.importKey({
            kty: "OKP",
            d:"z7sgkrcwC8FdNUl5VVKgFw0mRpkTVHPWYqxJvoUGdyw",
            crv:"Ed25519",
            kid:"k1",
            x:"WvfMIvH0outwLZk52LpY9lZjBRbVsdweqKZPogozyhg"
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    it("Alice import p256 key", function (done) {
        aries.kms.importKey({
            kty: "EC",
            crv:"P-256",
            kid:"kid",
            alg:"EdDSA",
            x:"PgMD0SNj1jNPZhfzrXZPOrLnKvfXrfRHvp0h-K6B7KQ",
            y:"3OzFHfWGlk-pH-iGZOcka0LhgpL1-Yn67fTizBbp1Nc",
            d:"jPJSme0wUa-m61EGzQCnCNG-1Y21Kljpf5lJH_gMrRY"
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })
}
