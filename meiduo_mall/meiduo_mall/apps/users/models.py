from django.conf import settings
from django.db import models

# Create your models here.

from django.contrib.auth.models import AbstractUser

# 我们重写用户模型类, 继承自 AbstractUser
from itsdangerous import TimedJSONWebSignatureSerializer, BadData


class User(AbstractUser):
    """自定义用户模型类"""

    # 在用户模型类中增加 mobile 字段
    mobile = models.CharField(max_length=11, unique=True, verbose_name='手机号')
    email_active = models.BooleanField(default=False, verbose_name='邮箱验证状态')
    # 对当前表进行相关设置:
    class Meta:
        db_table = 'tb_users'
        verbose_name = '用户'
        verbose_name_plural = verbose_name

    # 在 str 魔法方法中, 返回用户名称
    def __str__(self):
        return self.username

    def generate_verify_email_url(self):
        """
        生成邮箱验证链接
        :return:
        """
        #调用itsdangerous中的类，生成对象
        serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                        expires_in=3600*24)
        #拼接参数
        data = {'user_id':self.id,'email':self.email}
        #生成TOken值，这个值是bytes类型，所以解码为str类型
        token = serializer.dumps(data).decode()
        #拼接 url
        virify_url = settings.EMAIL_VERIFY_URL + '?token=' + token
        # 返回
        return virify_url

    #定义验证函数
    @staticmethod
    def check_verify_email_token(token):
        """
        验证token并提取user
        :param token:
        :return:
        """
        #调用 itsdangerous类生成类对象
        #验证呢个邮件有效期：1天
        serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                                     expires_in=3600*24)
        try:
            #解密传入的token值
            data = serializer.loads(token)
        except BadData:
            #如果token没有值会报错
            return  None
        else:
            #如果有值就获取
            user_id = data.get('user_id')
            email = data.get('email')
        #获取到值之后，尝试从User表中获取相应的用户
        try:
            user = User.objects.get(id=user_id,email=email)
        except User.DoesNotExist:
            #如果用户不存在，返回个None
            return None
        else:
            #如果存在则直接返回
            return user

