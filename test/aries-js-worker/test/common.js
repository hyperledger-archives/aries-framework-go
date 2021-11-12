/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import { environment } from "./environment.js";

var AriesWeb = null;
var AriesREST = null;

(async function  () {
    await import('/base/node_modules/@hyperledger/aries-framework-go/dist/web/aries.js')
    AriesWeb = Aries.Framework

    await import('/base/node_modules/@hyperledger/aries-framework-go/dist/rest/aries.js')
    AriesREST = Aries.Framework
})();

async function waitUntil(f, timeoutMs) {
    return new Promise((resolve, reject) => {
        let timeWas = new Date();
        let wait = setInterval(function() {
            if (f()) {
                clearInterval(wait);
                resolve();
            } else if (new Date() - timeWas > timeoutMs) {
                clearInterval(wait);
                reject();
            }
        }, 100);
    });
}

export async function newAries(dbNS = '', label= "dem-js-agent", httpResolver = [], contextProviders = [], mediaTypeProfiles = ["didcomm/aip2;env=rfc19"]) {
    await waitUntil(() => AriesWeb !== null, 5000);

    return new AriesWeb({
        assetsPath: "/base/public/aries-framework-go/assets",
        "agent-default-label": label,
        "http-resolver-url": httpResolver,
        "auto-accept": true,
        "outbound-transport": ["ws", "http"],
        "transport-return-route": "all",
        "log-level": environment.LOG_LEVEL,
        "db-namespace": dbNS,
        "context-provider-url": contextProviders,
        "media-type-profiles": mediaTypeProfiles
    })
}

export async function newAriesREST(controllerUrl, mediaTypeProfiles = ["didcomm/v2"]) {
    await waitUntil(() => AriesREST !== null, 5000);

    return new AriesREST({
        assetsPath: "/base/public/aries-framework-go/assets",
        "agent-rest-url": controllerUrl,
        "agent-rest-wshook": controllerUrl.replace("http://", "ws://") + "/ws",
        "media-type-profiles": mediaTypeProfiles
    })
}

export async function healthCheck(url, timeout, msgTimeout) {
    if (url.startsWith("http")) {
        return testHttpUrl(url, timeout, msgTimeout)
    } else if (url.startsWith("ws")) {
        return testWsUrl(url, timeout, msgTimeout)
    } else {
        throw new Error(`unsupported protocol for url: ${url}`)
    }
}

function testHttpUrl(url, timeout, msgTimeout) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(msgTimeout)), timeout)
        // TODO HTTP GET for the HTTP inbound transport endpoint (eg. http://0.0.0.0:10091) returns 405. Axios fails, fetch() doesn't.
        //  Golang's http.Get() does not fail for non 2xx codes.
        fetch(url).then(
            resp => {
                clearTimeout(timer);
                resolve(resp)
            },
            err => {
                clearTimeout(timer);
                console.log(err);
                reject(new Error(`failed to fetch url=${url}: ${err.message}`))
            }
        )
    })
}

function testWsUrl(url, timeout, msgTimeout) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(msgTimeout)), timeout)
        const ws = new WebSocket(url)
        ws.onopen = () => {
            clearTimeout(timer);
            resolve()
        }
        ws.onerror = err => {
            clearTimeout(timer);
            reject(new Error(err.message))
        }
    })
}

export function watchForEvent(agent, options) {
    const defaultTimeout = 10000
    const defaultTimeoutError = "time out while waiting for event"

    if (options === undefined) {
        options = {}
    }

    if (!options.timeout) {
        options.timeout = defaultTimeout
    }

    if (!options.timeoutError) {
        options.timeoutError = defaultTimeoutError
    }

    if (!options.topic) {
        options.topic = "all"
    }

    return new Promise((resolve, reject) => {
        setTimeout(_ => reject(new Error(options.timeoutError)), options.timeout)
        const stop = agent.startNotifier(event => {
            try {
                assert.property(event, "isErr")
                assert.isFalse(event.isErr)
                assert.property(event, "payload")

                let payload = event.payload;

                if (options.connectionID && payload.Properties.connectionID !== options.connectionID) {
                    return
                }

                if (options.stateID && payload.StateID !== options.stateID) {
                    return
                }

                if (options.type && payload.Type !== options.type) {
                    return
                }

                if (options.messageID && payload.Message['@id'] !== options.messageID) {
                    return
                }

                if (options.messageThreadID && payload.Message['~thread']['thid'] !== options.messageThreadID) {
                    return
                }

                stop()
                resolve(payload)
            } catch (e) {
                stop()
                reject(e)
            }
        }, [options.topic])
    })
}
