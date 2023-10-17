<template>
    <div class="login-container">
      <el-form ref="loginForm" :model="loginForm" :rules="rules" class="login-form">
        <h2 class="login-title">登录</h2>
        <el-form-item prop="username">
          <el-input v-model="loginForm.username" placeholder="Username"></el-input>
        </el-form-item>
        <el-form-item prop="password">
          <el-input type="password" v-model="loginForm.password" placeholder="Password"></el-input>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="submitForm('loginForm')">Login</el-button>
        </el-form-item>
      </el-form>
    </div>
  </template>
  
  <script>
  import { Form, FormItem, Input, Button } from 'element-ui';
  
  export default {
    name: 'Login',
    components: {
      [Form.name]: Form,
      [FormItem.name]: FormItem,
      [Input.name]: Input,
      [Button.name]: Button,
    },
    data() {
      return {
        loginForm: {
          username: '',
          password: '',
        },
        rules: {
          username: [
            { required: true, message: '请输入用户名！', trigger: 'blur' },
          ],
          password: [
            { required: true, message: '请输入密码！', trigger: 'blur' },
          ],
        },
      };
    },
    methods: {
      submitForm(formName) {
        this.$refs[formName].validate(valid => {
          if (valid) {
            alert('Login Success!');
          } else {
            console.log('Login failed');
            return false;
          }
        });
      },
    },
  };
  </script>
  
  <style scoped>
  .login-container {
    width: 400px;
    margin: 100px auto;
  }
  .login-form {
    padding: 20px;
    background-color: #fff;
    border-radius: 4px;
    box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
  }
  .login-title {
    text-align: center;
    margin-bottom: 30px;
  }
  </style>
  