<template>
  <div id="home">
    <div class="content-wrapper">
      <div class="title">
        <h1>输入以开始检测</h1>
      </div>
      <div class="urlInput">
        <el-input v-model="input" placeholder="请输入待检测url"></el-input>
        <el-button @click="detecte" class="DeButton">GO!</el-button> 
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'HelloWorld',
  data(){
     return{
        input:''
     }
  },
  props: {
    msg: String,
  },
  methods:{
    detecte(){
      console.log(this.input)
      this.$axios.post('/index/',JSON.stringify(this.input)).then(res => {
              if(res.data != 'error'){
                this.$message({
                type: "success",
                message: "目标url使用的服务器类型是:"+res.data
            })}else{
              this.$message.error(res.data.msg||"操作失败,请输入正确的url")
            }
    })
  }
}
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
.content-wrapper{
  width:100%;
}
.title{
  margin-top:10%
}
.urlInput{
  width:400px;
  margin:0 auto;

}
.DeButton{
  margin-top: 20px;
}
</style>
