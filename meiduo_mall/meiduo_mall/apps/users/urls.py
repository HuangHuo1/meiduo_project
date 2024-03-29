from django.conf.urls import url


from meiduo_mall.apps.users import views

# urlpatterns = [
#     url(r'^register/$', views.RegisterView.as_view(), name='register'),
#     url(r'^usernames/(?P<username>\w{5,20})/count/$', views.UsernameCountView.as_view()),
#     url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/$', views.MobileCountView.as_view()),
# ]
urlpatterns = [
    # 注册
    url(r'^register/$', views.RegisterView.as_view(), name='register'),
    # 判断用户名是否重复
    url(r'^usernames/(?P<username>\w{5,20})/count/$', views.UsernameCountView.as_view()),
    # 判断手机号是否重复
    url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/$', views.MobileCountView.as_view()),
    # 用户名登录
    url(r'^login/$', views.LoginView.as_view(), name='login'),
    # 退出登录
    url(r'^logout/$', views.LogoutView.as_view(), name='logout'),
    # 用户中心
    url(r'^info/$', views.UserInfoView.as_view(), name='info'),
    #绑定邮箱
    url(r'^emails/$', views.EmailView.as_view(), name='emails'),
    #验证邮箱
    url(r'^emails/verification/$', views.VerifyEmailView.as_view()),
]