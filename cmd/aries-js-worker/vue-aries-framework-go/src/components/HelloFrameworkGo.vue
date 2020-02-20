<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
 -->

<template>
  <div class="hello">
    <h1>{{ msg }}</h1>

    <div>
      <button @click="createInvitation()">Create Invitation</button>
    </div>
    <div>
      <label for="test-output">Invitation: </label>
      <textarea id="test-output" rows="15" cols="70"></textarea>
    </div>

  </div>
</template>

<script>
  export default {
    name: 'HelloFrameworkGo',
    props: {
      msg: String
    },
    methods: {
      async createInvitation () {
        const invitation = await this.$aries.didexchange.createInvitation("{}")
        document.querySelector("#test-output").value = JSON.stringify(invitation, undefined, 4)
      }
    }
  }
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}
</style>
