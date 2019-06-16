from django.conf.urls import url




# urlpatterns = [
#     url(r'^register/$', views.RegisterView.as_view(), name='register'),
#     url(r'^usernames/(?P<username>\w{5,20})/count/$', views.UsernameCountView.as_view()),
#     url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/$', views.MobileCountView.as_view()),
# ]
from oauth import views

urlpatterns = [
    url(r'^qq/authorization/$', views.QQURLView.as_view()),
    url(r"^oauth_callback/$",views.QQUserView.as_view())
]