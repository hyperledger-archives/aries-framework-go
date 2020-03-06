/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST} from "../common.js"
import {environment} from "../environment.js";

const agentControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

// scenarios
describe("VDRI", function () {
    let agents

    before(async () => {
        await Promise.all([newAries('demo','demo-agent', ["sidetree@http://localhost:48326/document"]), newAriesREST(agentControllerApiUrl)]).then(
            values => {
                agents = values
            }
        ).catch(
            err => {
                throw err
            }
        )
    })

    after(() => {
        agents.forEach(
            (agent) => {
                agent.destroy()
            }
        )
    })

    it("create public DID using VDRI in WASM and REST Client mode", async function (done) {
        if (!agents || agents.length == 0) {
            done("invalid agents initialized")
        }

        agents.forEach(
            async (agent) => {
                var resp
                try {
                    resp = await agent.vdri.createPublicDID({
                        method: "sidetree",
                        header: '{"alg":"","kid":"","operation":"create"}'
                    })
                } catch (err) {
                    done(err)
                }
                console.log("resp is ", resp)
            }
        )
        done()
    })
})
