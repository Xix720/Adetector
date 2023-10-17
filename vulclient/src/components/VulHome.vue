<template>
  <div class="vulnerability-detector">
    <h1 style="color:black">欢迎使用ADetector</h1>
    <!-- <div class="background">
      <img :src="imgSrc" width="100%" height="100%" alt="" />
    </div> -->

    <div class="search-container">
      <el-input
        v-model="input"
        placeholder="请输入URL"
        class="search-input"
      ></el-input>
      <el-button
        type="primary"
        icon="el-icon-search"
        circle
        class="search-button"
        @click="onDetect"
      ></el-button>
    </div>

    <el-dialog title="检测结果" :visible.sync="dialogTableVisible">
      <el-table :data="vuls">
        <el-table-column prop="type" label="漏洞类型" width="180"></el-table-column>
        <el-table-column prop="id" label="漏洞名称" min-width="140"></el-table-column>
        <el-table-column prop="payload" label="攻击载荷" min-width="180"></el-table-column>
        <el-table-column prop="severity" label="严重性" width="100">
          <template slot-scope="scope">
            <el-tag :type="severityTagType(scope.row.severity)">{{ scope.row.severity }}</el-tag>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>
  </div>
</template>

<script>
import router from '@/router';
export default {
  data() {
    return {
      vuls: [],
      dialogTableVisible: false,
      input: "",
    };
  },
  methods: {
    severityTagType(severity) {
        switch (severity) {
          case "高":
            return "danger";
          case "中":
            return "warning";
          case "低":
            return "info";
          default:
            return "";
        }
      },
    onDetect() {
      // 在这里执行检测操作
      console.log("检测按钮被点击");
      console.log(this.input)
      var loading = this.$loading({
          lock: true,
          text: '正在检测中，请勿刷新页面',
          background: 'rgba(0, 0, 0, 0.7)'
        });
      this.$axios.post('/fingerRec/',JSON.stringify(this.input)).then(res => {
        console.log(res.data)
        if(res.data == 'Yes'){
          loading.close()
          this.$confirm('检测到目标Url使用了Apache服务，是否启用快速检测模式?', '提示', {
          confirmButtonText: '是',
          cancelButtonText: '否',
          type: 'warning'
        }).then(() => {
          loading = this.$loading({
              lock: true,
              text: '正在检测中，请勿刷新页面',
              background: 'rgba(0, 0, 0, 0.7)'
            });
          this.$axios.post('/fastdetection/',JSON.stringify(this.input)).then(res =>{
            console.log(res.data)
            this.vuls = res.data
            this.dialogTableVisible = true
            loading.close()
          })
        }).catch(() => {
            loading = this.$loading({
              lock: true,
              text: '正在检测中，请勿刷新页面',
              background: 'rgba(0, 0, 0, 0.7)'
            });
            this.$axios.post('/fuzz/',JSON.stringify(this.input)).then(res =>{
              console.log(res.data)
              this.vuls = res.data
              this.dialogTableVisible = true
              loading.close()
          })    
        });
        }else{
          this.$axios.post('/fuzz/',JSON.stringify(this.input)).then(res =>{
            print(res.data)
            this.vuls = res.data
            this.dialogTableVisible = true
            loading.close()
          })
        }
          
            })
      }
    }
}
             
</script>

<style scoped>

  .background{
    height: 100%;
    width:100%;  
    z-index:-1;
    position: absolute;
    left: 0;
    top: 0;
}

.vulnerability-detector {
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 600px;
  margin: 120px auto;
  padding: 30px;
  box-sizing: border-box;
}


.search-container {
  display: flex;
  align-items: center;
  width: 100%;
  max-width: 600px;
  margin-bottom: 20px;
  background-color: #fff;
  border: 1px solid #dcdfe6;
  border-radius: 24px;
  overflow: hidden;
  box-shadow: 0 1px 6px rgba(32, 33, 36, 0.28);
}

.search-input {
  flex-grow: 1;
  margin: 0;
  padding: 8px 16px;
  font-size: 14px;
  border: none;
  outline: none;
  border-radius: 0; /* 移除圆角 */
  background-color: transparent; /* 设置背景透明 */
}

.search-button {
  padding: 0;
  border-radius: 50%;
  height: 30px;
  width: 35px;
  margin-right: 8px;
}
</style>
