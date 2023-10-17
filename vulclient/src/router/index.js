import Vue from "vue";
import Router from 'vue-router';
// import { component } from "vue/types/umd";
// import Home from '../components/Home.vue'

Vue.use(Router)

export default new Router({
    routes:[
        {
            path:'/',
            redirect:'/homepage',
        },
        {
            path:'/home',
            // component:Home
            component: () =>import('@/components/Home') //路由懒加载
            // component: resolve =>require(['@/components/Home'],resolve) //异步组件
            
        },
        {
            path:'/login',
            component: () =>import('@/components/login') //路由懒加载
            
        },
        {
            path:'/homepage',
            component: () =>import('@/components/VulHome') //路由懒加载
            
        },
        {
            path:'/results',
            component: () =>import('@/components/VulResults') //路由懒加载
            
        },
                        
    ],
    mode:'history'
})