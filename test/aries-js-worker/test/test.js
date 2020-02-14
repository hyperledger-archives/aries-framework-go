/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const assert = chai.assert

async function loadAries() {
    return new Aries.Framework({
        assetsPath: "/base/public/aries-framework-go/assets",
        "agent-default-label": "dem-js-agent",
        "http-resolver-url": "",
        "auto-accept": true,
        "outbound-transport": ["ws", "http"],
        "transport-return-route": "all",
        "log-level": "debug"
    })
}

describe("_test", function() {
    var aries
    before(async () => {
        return new Promise((resolve, reject) => {
            loadAries().then(
                a => {aries = a; resolve()},
                err => reject(new Error(err.message))
            )
        })
    })

    after(() => {
        aries.destroy()
    })

    describe("#_echo()", function() {
        it("should echo input", async function() {
            const expected = "sup"
            const result =  await aries._test._echo(expected)
            assert.isObject(result)
            assert.property(result, "echo")
            assert.equal(result.echo, expected)
        })
    })
})

