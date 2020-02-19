/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Vue from 'vue'
import App from './App.vue'

import * as Aries from "@hyperledger/aries-framework-go"

async function loadAries() {
    Vue.prototype.$aries = await new Aries.Framework({
        assetsPath: "/aries-framework-go/assets",
        "agent-default-label":"dem-js-agent",
        "http-resolver-url":[],
        "auto-accept":true,
        "outbound-transport":["ws","http"],
        "transport-return-route":"all",
        "log-level":"debug"
    })
}

loadAries()

Vue.config.productionTip = false

new Vue({
  render: h => h(App),
}).$mount('#app')
