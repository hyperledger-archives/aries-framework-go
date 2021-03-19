/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
import {environment} from "../environment.js";
import {didExchangeClient, newDIDExchangeClient, newDIDExchangeRESTClient} from "../didexchange/didexchange_e2e.js";
import {watchForEvent} from "../common.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.SECOND_USER_HOST}:${environment.SECOND_USER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'
const actionsTopic = "out-of-band_actions"

describe("Outofband - New connection after Alice sends an ouf-of-band invitation to Bob", async function () {
    describe(restMode, function () {
        outofbandInvitation(restMode)
    })
    describe(wasmMode, function () {
        outofbandInvitation(wasmMode)
    })
})

export function createInvitation(router, label) {
    return {
        label: label,
        router_connection_id: router,
    }
}

async function outofbandInvitation(mode) {
    let didexClient

    before(async () => {
        didexClient = await client(mode)
    })

    after(async () => {
        await didexClient.destroy()
    })

    let invitation;
    it("Alice constructs an out-of-band invitation", async function () {
        invitation = await didexClient.agent1.outofband.createInvitation({
            label: "Alice",
            router_connection_id: didexClient.agent1RouterConnection
        })
    })

    it("Bob accepts the invitation and connects with Alice", async function () {
        let checked = checkConnection(mode, didexClient.agent1, didexClient.agent2, invitation.invitation['@id'], didexClient.agent1RouterConnection)

        await didexClient.agent2.outofband.acceptInvitation({
            my_label: "Bob",
            invitation: invitation.invitation,
            router_connections: didexClient.agent2RouterConnection,
        })

        await checked
    })
}

async function client(mode) {
    if (mode === restMode) {
        return await newDIDExchangeRESTClient(agent2ControllerApiUrl, agent1ControllerApiUrl)
    }

    let client = await newDIDExchangeClient("alice", "bob")
    await client.setupRouter()
    return client
}

export async function checkConnection(mode, inviter, invitee, expected, router) {
    let connections = Promise.all([
        didExchangeClient.watchForConnection(inviter, "completed").then(async (id) => {
            let conn = await connection(inviter, id)
            assert.equal(expected, conn.InvitationID)
            return id
        }),
        didExchangeClient.watchForConnection(invitee, "completed").then(async (id) => {
            let conn = await connection(invitee, id)
            assert.equal(expected, conn.ParentThreadID)
            return id
        })
    ])

    if (mode === wasmMode) {
        didExchangeClient.acceptExchangeRequest(inviter, "", router)
    }

    return await connections
}

export async function connectAgents(mode, inviter, invitee) {
    let invitation = await inviter.outofband.createInvitation({
        label: getRandom(1, 10) + "_" + getRandom(1, 10),
        router_connection_id: inviter.routerConnection
    })

    let checked = checkConnection(mode, inviter, invitee, invitation.invitation['@id'], inviter.routerConnection)

    await invitee.outofband.acceptInvitation({
        my_label: getRandom(1, 10) + "_" + getRandom(1, 10),
        invitation: invitation.invitation,
        router_connections: invitee.routerConnection,
    })

    return await checked
}

export function getRandom(min, max) {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function connection(agent, conn) {
    let res = await agent.didexchange.queryConnectionByID({
        id: conn
    })

    return res.result
}

export async function getAction(agent) {
    return await watchForEvent(agent, {
        topic: actionsTopic,
    })
}
