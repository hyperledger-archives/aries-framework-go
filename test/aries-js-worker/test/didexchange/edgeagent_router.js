/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import { newAries, healthCheck } from "../common.js"
import { environment } from "../environment.js"

const routerHttpUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_HTTP_INBOUND_PORT}`
const routerWsUrl = `${environment.WS_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_WS_INBOUND_PORT}`
const routerControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_API_PORT}`

const routerConnPath = "/connections"
const routerCreateInvitationPath = `${routerControllerApiUrl}${routerConnPath}/create-invitation`

describe("DID-Exchange between an Edge Agent and a router", function() {
    var aries
    var invitation

    before(async () => {
        return new Promise((resolve, reject) => {
            newAries().then(
                a => {aries = a; resolve()},
                err => reject(new Error(err.message))
            )
        })
    })

    after(() => {
        aries.destroy()
    })

    it(`Router is running on "${routerHttpUrl},${routerWsUrl}" with controller "${routerControllerApiUrl}"`, async function() {
        await healthCheck(routerHttpUrl, 5000, "healthCheck timeout!")
        await healthCheck(routerWsUrl, 5000, "healthCheck timeout!")
        await healthCheck(routerControllerApiUrl, 5000, "healthCheck timeout!")
    })

    it("Edge Agent receives an invitation from the router via the controller API", async function() {
        const response = await axios.post(routerCreateInvitationPath)
        invitation = response.data.invitation
        assert.isObject(invitation)
        assert.property(invitation, "serviceEndpoint")
        assert.property(invitation, "recipientKeys")
        assert.property(invitation, "@id")
        assert.property(invitation, "label")
        assert.property(invitation, "@type")
        assert.equal(invitation["@type"], "https://didcomm.org/didexchange/1.0/invitation")
    })

    it("Edge Agent accepts the invitation from the router", function(done) {
        aries.startNotifier(notice => {
            try {
                assert.isFalse(notice.isErr)
                assert.property(notice, "payload")
                const connection = notice.payload
                assert.property(connection, "connection_id")
                aries.didexchange.acceptInvitation(connection.connection_id)
            } catch (err) {
                done(err)
            }
            done()
        }, ["connections"])
        aries.didexchange.receiveInvitation(invitation)
    })

    it("Edge Agent validates that the connection's state is 'completed'", function(done) {
        aries.startNotifier(notice => {
            try {
                assert.isObject(notice)
                assert.property(notice, "isErr")
                assert.isFalse(notice.isErr)
                assert.property(notice, "payload")
                assert.property(notice.payload, "state")
            } catch (err) {
                done(err)
            }
            if (notice.payload.state === "completed") {
                done()
            }
        }, ["connections"])
    })
})

