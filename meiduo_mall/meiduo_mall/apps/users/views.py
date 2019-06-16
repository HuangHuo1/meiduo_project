
import json
import logging

logger = logging.getLogger('django')
from django import http
from django.contrib.auth import login, authenticate, logout
from django.db import DatabaseError
from django.shortcuts import render, redirect
import re
# Create your views here.
from django.urls import reverse
from django.views import View
from django_redis import get_redis_connection

from meiduo_mall.utils.response_code import RETCODE
from users.models import User
from users.utils import LoginRequiredMixin

class VerifyEmailView(View):
    #验证邮箱
    def get(self,request):
        """
        实现邮箱验证逻辑
        :param request:
        :return:
        """
        #接受参数
        token = request.GET.get('token')
        #检验参数
        if not token:
            return http.HttpResponseForbidden('缺少token')
        #调用之前封装好的方法，江token传入将其解密
        user = User.check_verify_email_token(token)
        if not user:
            return http.HttpResponseForbidden('无效的token')
        #修改email_active的的状态为激活
        try:
            user.email_active = True
            user.save()
        except Exception as f:
            logger.error(f)
            return http.HttpResponseForbidden('邮件激活失败')
        #返回邮件验证结果
        return redirect(reverse('users:info'))




class UserInfoView(LoginRequiredMixin, View):

    def get(self, request):
        '''
        返回用户中心页面
        :param request:
        :return:
        '''

        # if request.user.is_authenticated:
        #     return render(request, 'user_center_info.html')
        # else:
        #     return render(request,'404.html')
        context = {
            'username': request.user.username,
            'mobile': request.user.mobile,
            'email': request.user.email,
            'email_active': request.user.email_active
        }
        return render(request, 'user_center_info.html', context)


class EmailView(View):
    """
    添加邮箱
    """

    def put(self, request):
        """
        实现添加邮箱逻辑
        :param request:
        :return:
        """
        # 接受参数
        json_dict = json.loads(request.body.decode())
        email = json_dict.get('email')
        # 检验参数
        if not email:
            return http.HttpResponseForbidden('缺少email参数')
        if not re.match(r'^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return http.HttpResponseForbidden('请输入正确email')
        # 赋值 email 字段 保存
        try:
            request.user.email = email
            request.user.save()
        except  Exception as f:
            logger.error(f)
            return http.JsonResponse({'code': RETCODE.DBERR, 'errmsg': '邮箱添加失败'})
        #导入邮件异步发送程序
        from celery_tasks.email.tasks import send_verify_email
        verify_url =request.user.generate_verify_email_url()

        send_verify_email.delay(email,verify_url)


        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '10k'})


class LogoutView(View):
    def get(self, request):
        '''
        退出登录
        :param request:
        :return:
        '''
        # 1.清理session
        logout(request)

        # 2.获取response对象
        response = redirect(reverse('contents:index'))

        # 3.使用response对象, 删除cookie
        response.delete_cookie('username')

        # 4.返回
        return response


class LoginView(View):

    def post(self, request):
        '''
        接收参数, 检验参数, 决定用户是否登录成功
        :param request:
        :return:
        '''
        # 1.接受参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        remembered = request.POST.get('remembered')

        # 2.校验(全局 + 单个)
        if not all([username, password]):
            return http.HttpResponseForbidden('缺少必传参数')

        # 单个检验
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('用户名不符合5-20位的格式')

        if not re.match(r'^[a-zA-Z0-9]{8,20}$', password):
            return http.HttpResponseForbidden('密码不符合8-20位的格式')

        # 3.认证用户是否登录
        user = authenticate(username=username, password=password)

        # 4.如果没有当前用户, 报错
        if user is None:
            return render(request, 'login.html', {'account_errmsg': '用户名或密码错误'})

        # 5.设置状态保持
        login(request, user)

        # 6.判断是否记住登录状态
        if remembered != 'on':
            # 没有勾选:
            request.session.set_expiry(0)
        else:
            # 勾选状态: None: 两周
            request.session.set_expiry(None)

        # response = redirect(reverse('contents:index'))
        # 获取跳转过来的地址:
        next = request.GET.get('next')
        # 判断参数是否存在:
        if next:
            # 如果是从别的页面跳转过来的, 则重新跳转到原来的页面
            response = redirect(next)
        else:
            # 如果是直接登陆成功，就重定向到首页
            response = redirect(reverse('contents:index'))

        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)

        # 7.重定向到首页
        return response

    def get(self, request):
        '''
        返回登录页面
        :param request:
        :return:
        '''
        return render(request, 'login.html')


class MobileCountView(View):

    def get(self, request, mobile):
        '''
        检验手机号是否重复: 把接收的手机号扔到mysql查询,返回结果
        :param request:
        :param username:
        :return:
        '''
        # 1.mysql查询mobile对应的个数
        count = User.objects.filter(mobile=mobile).count()

        # 2.返回
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'ok',
            'count': count
        })


class UsernameCountView(View):

    def get(self, request, username):
        '''
        检验用户名是否重复: 把接收的用户名扔到mysql查询,返回结果
        :param request:
        :param username:
        :return:
        '''
        # 1.mysql查询username对应的个数
        count = User.objects.filter(username=username).count()

        # 2.返回
        return http.JsonResponse({
            'code': RETCODE.OK,
            'errmsg': 'ok',
            'count': count
        })


class RegisterView(View):

    def post(self, request):
        '''
        接收用户发过来的注册信息, 保存到mysql
        :param request:
        :return:
        '''
        # 1.接收参数
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        mobile = request.POST.get('mobile')
        allow = request.POST.get('allow')
        sms_code_client = request.POST.get('sms_code')

        # 2.检验参数(总体检验 + 单个检验)
        if not all([username, password, password2, mobile, allow]):
            return http.HttpResponseForbidden('缺少必传参数')

        # 单个检验
        if not re.match(r'^[a-zA-Z0-9_-]{5,20}$', username):
            return http.HttpResponseForbidden('用户名不符合5-20位的格式')

        if not re.match(r'^[a-zA-Z0-9]{8,20}$', password):
            return http.HttpResponseForbidden('密码不符合8-20位的格式')

        if password != password2:
            return http.HttpResponseForbidden('两次输入密码不一致')

        if not re.match(r'^1[3456789]\d{9}$', mobile):
            return http.HttpResponseForbidden('手机号不符合')

        if allow != 'on':
            return http.HttpResponseForbidden('请勾选用户协议')

        # 2.1 链接redis
        redis_conn = get_redis_connection('verify_code')

        # 2.2 获取redis中的短信验证码
        sms_code_server = redis_conn.get('sms_code_%s' % mobile)
        if sms_code_server is None:
            return render(request, 'register.html', {'sms_code_errmsg': '无效的短信验证码'})

        # 2.3 判断两个验证码是否一致
        if sms_code_server.decode() != sms_code_client:
            return render(request, 'register.html', {'sms_code_errmsg': '前端输入的短信验证码有误'})

        # 3.往mysql存(User)
        try:
            user = User.objects.create_user(username=username, password=password, mobile=mobile)
        except DatabaseError:

            return render(request, 'register.html', {'register_errmsg': '保存数据失败'})

        # 保持状态:
        login(request, user)

        response = redirect(reverse('contents:index'))

        # 往cookie中写入username
        response.set_cookie('username', user.username, max_age=3600 * 24 * 15)

        # 4.返回结果
        # return http.HttpResponse('保存成功,跳转到首页')
        return response

    def get(self, request):
        '''
        返回register.html(注册页面)
        :param request:
        :return:
        '''
        return render(request, 'register.html')

