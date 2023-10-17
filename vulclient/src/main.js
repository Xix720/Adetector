import Vue from 'vue'
import App from './App.vue'
import ElementUI from 'element-ui'
import 'element-ui/lib/theme-chalk/index.css';
import axios from 'axios';
import 'font-awesome/css/font-awesome.min.css'
import router from './router/index'

axios.defaults.baseURL = 'http://127.0.0.1:8000';
Vue.prototype.$axios = axios  //挂载到原型，可以在全局使用
Vue.config.productionTip = false
Vue.use(ElementUI)
new Vue({
  router,
  render: h => h(App),
}).$mount('#app')
