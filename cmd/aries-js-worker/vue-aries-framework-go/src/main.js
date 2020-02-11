/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import Vue from 'vue'
import App from './App.vue'

import { Aries } from "@hyperledger/aries-framework-go"
Object.defineProperty(Vue.prototype, "$aries", { value: new Aries({}) })

Vue.config.productionTip = false

new Vue({
  render: h => h(App),
}).$mount('#app')
