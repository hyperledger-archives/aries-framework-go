/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

export async function newAries() {
    return new Aries.Framework({
        assetsPath: "/base/public/aries-framework-go/assets",
        "agent-default-label": "dem-js-agent",
        "http-resolver-url": [],
        "auto-accept": true,
        "outbound-transport": ["ws", "http"],
        "transport-return-route": "all",
        "log-level": "debug"
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
            resp => {clearTimeout(timer); resolve(resp)},
            err => {clearTimeout(timer); console.log(err); reject(new Error(`failed to fetch url=${url}: ${err.message}`))}
        )
    })
}

function testWsUrl(url, timeout, msgTimeout) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(msgTimeout)), timeout)
        const ws = new WebSocket(url)
        ws.onopen = () => {clearTimeout(timer); resolve()}
        ws.onerror = err => {clearTimeout(timer); reject(new Error(err.message))}
    })
}
