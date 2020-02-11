<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
 -->

<template>
  <div class="hello">
    <h1>{{ msg }}</h1>

    <div>
      <label for="test-input">Input: </label>
      <input type="text" id="test-input"/>
      <button @click="handleInput()">echo</button>
    </div>
    <div>
      <label for="test-output">Output: </label>
      <output id="test-output"></output>
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
      async handleInput () {
        const invite = document.querySelector("#test-input").value
        const connID = await this.$aries._test._echo(invite)
        document.querySelector("#test-output").value = connID
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
