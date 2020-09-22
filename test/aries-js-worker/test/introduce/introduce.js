/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
import {environment} from "../environment.js";
import {newAries, newAriesREST, watchForEvent} from "../common.js"
import {
    checkConnection,
    connectAgents,
    createRequest,
    getAction as getOutofbandAction
} from "../outofband/outofband.js";
import {didExchangeClient, getMediatorConnection} from "../didexchange/didexchange_e2e.js";

const agent1ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.SECOND_USER_HOST}:${environment.SECOND_USER_API_PORT}`
const agent2ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.USER_HOST}:${environment.USER_API_PORT}`
const agent3ControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.THIRD_USER_HOST}:${environment.THIRD_USER_API_PORT}`

const restMode = 'rest'
const wasmMode = 'wasm'
const actionsTopic = "introduce_actions"

describe("Introduce - Alice has Carol's public out-of-band request", async function () {
    describe(restMode, function () {
        skipProposal(restMode)
    })
    describe(wasmMode, function () {
        skipProposal(wasmMode)
    })
})

describe("Introduce - Alice has Carol's public out-of-band request. The protocol starts with introduce request.", async function () {
    describe(restMode, function () {
        skipProposalWithRequest(restMode)
    })
    describe(wasmMode, function () {
        skipProposalWithRequest(wasmMode)
    })
})

describe("Introduce - Bob sends a response with approve and an out-of-band request.", async function () {
    describe(restMode, function () {
        proposal(restMode)
    })
    describe(wasmMode, function () {
        proposal(wasmMode)
    })
})

describe("Introduce - Bob sends a response with approve and an out-of-band request. The protocol starts with introduce request", async function () {
    describe(restMode, function () {
        proposalWithRequest(restMode)
    })
    describe(wasmMode, function () {
        proposalWithRequest(wasmMode)
    })
})

async function proposalWithRequest(mode) {
    let alice, bob, carol, destroy;
    before(async () => {
        [alice, bob, carol, destroy] = await createClients(mode)
    })

    after(async () => {
        await destroy()
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    let aliceAction;
    it("Bob sends introduce request to the Alice asking about Carol", async function () {
        aliceAction = getAction(alice)
        let conn = await bob.didexchange.queryConnectionByID({id: alice_bob[1]})
        await bob.introduce.sendRequest({
            "please_introduce_to": {"name": "Carol", "img~attach": {"content": {}}},
            "my_did": conn.result.MyDID,
            "their_did": conn.result.TheirDID
        })
    })

    let request;
    let bobAction;
    let carolAction;
    it("Alice sends introduce proposal back to the Bob and requested introduce", async function () {
        bobAction = getAction(bob)
        carolAction = getAction(carol)

        let conn = await alice.didexchange.queryConnectionByID({id: alice_carol[0]})
        await alice.introduce.acceptRequestWithRecipients({
            piid: (await aliceAction).Properties.piid,

            "recipient": {
                "to": {"name": "Bob", "img~attach": {"content": {}}},
                "my_did": conn.result.MyDID,
                "their_did": conn.result.TheirDID
            },
            "to": {"name": "Carol", "img~attach": {"content": {}}},
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve and provides an out-of-band request", async function () {
        request = await bob.outofband.createRequest(await createRequest(bob,"Bob"))
        await bob.introduce.acceptProposalWithOOBRequest({
            piid: (await bobAction).Properties.piid,
            "request": request.request
        })
    })

    it("Carol wants to know Bob and sends introduce response with approve", async function () {
        let outofbandAction = getOutofbandAction(carol)

        let checked = checkConnection(mode, bob, carol, request.request['@id'])

        await carol.introduce.acceptProposal({
            piid: (await carolAction).Properties.piid,
        })

        await carol.outofband.actionContinue({
            piid: (await outofbandAction).Message['@id'],
            label: "Bob",
            router_connections: await getMediatorConnection(carol),
        })

        await checked
    })
}

async function proposal(mode) {
    let alice, bob, carol, destroy;
    before(async () => {
        [alice, bob, carol, destroy] = await createClients(mode)
    })

    after(async () => {
        await destroy()
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    let request;
    let bobAction;
    let carolAction;
    it("Alice sends introduce proposal to the Bob and Carol", async function () {
        bobAction = getAction(bob);
        carolAction = getAction(carol)

        let conn1 = await alice.didexchange.queryConnectionByID({id: alice_bob[0]})
        let conn2 = await alice.didexchange.queryConnectionByID({id: alice_carol[0]})
        await alice.introduce.sendProposal({
            "recipients": [
                {
                    "to": {"name": "Carol", "img~attach": {"content": {}}},
                    "my_did": conn1.result.MyDID,
                    "their_did": conn1.result.TheirDID
                },
                {
                    "to": {"name": "Bob", "img~attach": {"content": {}}},
                    "my_did": conn2.result.MyDID,
                    "their_did": conn2.result.TheirDID
                }
            ]
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve and provides an out-of-band request", async function () {
        request = await bob.outofband.createRequest(await createRequest(bob,"Bob"))
        await bob.introduce.acceptProposalWithOOBRequest({
            piid: (await bobAction).Properties.piid,
            "request": request.request
        })
    })

    it("Carol wants to know Bob and sends introduce response with approve", async function () {
        let outofbandAction = getOutofbandAction(carol)

        let checked = checkConnection(mode, bob, carol, request.request['@id'])

        await carol.introduce.acceptProposal({
            piid: (await carolAction).Properties.piid,
        })

        await carol.outofband.actionContinue({
            piid: (await outofbandAction).Message['@id'],
            label: "Bob",
            router_connections: await getMediatorConnection(carol),
        })

        await checked
    })
}

async function skipProposalWithRequest(mode) {
    let alice, bob, carol, destroy;
    before(async () => {
        [alice, bob, carol, destroy] = await createClients(mode)
    })

    after(async () => {
        await destroy()
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    let request;
    let action;
    it("Bob sends introduce request to the Alice asking about Carol", async function () {
        action = getAction(alice)

        let conn = await bob.didexchange.queryConnectionByID({id: alice_bob[1]})
        await bob.introduce.sendRequest({
            "please_introduce_to": {"name": "Carol", "img~attach": {"content": {}}},
            "my_did": conn.result.MyDID,
            "their_did": conn.result.TheirDID
        })
    })

    let bobAction;
    it("Alice sends introduce proposal back to the requester with public out-of-band request", async function () {
        bobAction = getAction(bob)
        request = await carol.outofband.createRequest(await createRequest(carol,"Carol"))
        await alice.introduce.acceptRequestWithPublicOOBRequest({
            piid: (await action).Properties.piid,
            "request": request.request, "to": {"name": "Carol", "img~attach": {"content": {}}}
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve", async function () {
        let outofbandAction = getOutofbandAction(bob)

        let checked = checkConnection(mode, carol, bob, request.request['@id'])

        await bob.introduce.acceptProposal({
            piid: (await bobAction).Properties.piid,
        })

        await bob.outofband.actionContinue({
            piid: (await outofbandAction).Message['@id'],
            label: "Bob",
            router_connections: await getMediatorConnection(bob),
        })

        await checked
    })
}

async function skipProposal(mode) {
    let alice, bob, carol, destroy;
    before(async () => {
        [alice, bob, carol, destroy] = await createClients(mode)
    })

    after(async () => {
        await destroy()
    })

    let alice_bob, alice_carol;
    it("Bob and Carol have established connection with Alice", async function () {
        alice_bob = await connectAgents(mode, alice, bob)
        alice_carol = await connectAgents(mode, alice, carol)
    })

    let request;
    let bobAction;
    it("Alice sends introduce proposal to the Bob with Carol out-of-band request", async function () {
        bobAction = getAction(bob)

        let conn = await alice.didexchange.queryConnectionByID({id: alice_bob[0]})
        request = await carol.outofband.createRequest(await createRequest(carol,"Carol"))

        await alice.introduce.sendProposalWithOOBRequest({
            "request": request.request,
            "recipient": {
                "to": {"name": "Carol"},
                "my_did": conn.result.MyDID,
                "their_did": conn.result.TheirDID
            }
        })
    })

    it("Bob wants to know Carol and sends introduce response with approve", async function () {
        let outofbandAction = getOutofbandAction(bob)

        let checked = checkConnection(mode, carol, bob, request.request['@id'])

        await bob.introduce.acceptProposal({
            piid: (await bobAction).Properties.piid,
        })

        await bob.outofband.actionContinue({
            piid: (await outofbandAction).Message['@id'],
            label: "Bob",
            router_connections: await getMediatorConnection(bob),
        })

        await checked
    })
}

function clients(mode) {
    if (mode === restMode) {
        return Promise.all([
            newAriesREST(agent1ControllerApiUrl),
            newAriesREST(agent2ControllerApiUrl),
            newAriesREST(agent3ControllerApiUrl)
        ]);
    }

    return Promise.all([
        newAries("alice", "alice"),
        newAries("bob", "bob"),
        newAries("carol", "carol")
    ]);
}

async function createClients(mode) {
    let [alice, bob, carol] = await clients(mode)
    let aliceConn,bobConn,carolConn;

    if (mode === wasmMode) {
        aliceConn = await didExchangeClient.addRouter(mode, alice)
        bobConn = await didExchangeClient.addRouter(mode, bob)
        carolConn = await didExchangeClient.addRouter(mode, carol)
    }

    return [alice, bob, carol, async function() {
        if (mode === wasmMode) {
            await alice.mediator.unregister({"connectionID": aliceConn})
            await bob.mediator.unregister({"connectionID": bobConn})
            await carol.mediator.unregister({"connectionID": carolConn})
        }

        await alice.destroy()
        await bob.destroy()
        await carol.destroy()
    }]
}

async function getAction(agent) {
    return await watchForEvent(agent, {
        topic: actionsTopic,
    })
}
