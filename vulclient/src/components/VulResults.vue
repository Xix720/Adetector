<template>
    <div class="vulnerability-results">
      <h1>Results</h1>
      <el-table v-loading.fullscreen.lock="loading" :data="vulnerabilities" class="resultTab" border style="width: 60%;margin:0 auto">
        <el-table-column prop="type" label="漏洞类型" width="180"></el-table-column>
        <el-table-column prop="description" label="描述" min-width="300"></el-table-column>
        <el-table-column prop="severity" label="严重性" width="120">
          <template slot-scope="scope">
            <el-tag :type="severityTagType(scope.row.severity)">{{ scope.row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="120"></el-table-column>
      </el-table>
    </div>
  </template>
  
  <script>
  export default {
    name: "VulnerabilityResults",
    data() {
      return {
        loading: false,
        vulnerabilities: [
          { type: "SQL Injection", description: "注入点: /login", severity: "高", status: "未修复" },
          { type: "XSS", description: "反射型 XSS: /search", severity: "中", status: "已修复" },
          { type: "File Upload", description: "任意文件上传: /upload", severity: "高", status: "未修复" },
          { type: "File Upload", description: "任意文件上传: /upload", severity: "高", status: "未修复" },
        ],
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
    },
  };
  </script>
  
  <style scoped>
  .vulnerability-results {
    margin: 50px;
  }
  .resultTab{
    box-shadow: 0 1px 6px rgba(32, 33, 36, 0.28);
  }
  </style>
  