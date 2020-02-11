<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
 -->

<template>
  <div id="app">
    <p style="font-size:50px;font-weight: bold"><img src="https://raw.githubusercontent.com/hyperledger/aries-rfcs/1371a4807ead74c36ea7d5af909064ec491b78c1/collateral/Hyperledger_Aries_Logo_Color.png" height="100px" alt="Hyperledger Aries">Framework Go</p>
    <HelloFrameworkGo msg="Welcome to Your Hyperledger Aries Framework Go App!"/>
  </div>
</template>

<script>
import HelloFrameworkGo from './components/HelloFrameworkGo.vue'

export default {
  name: 'App',
  components: {
    HelloFrameworkGo
  }
}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
