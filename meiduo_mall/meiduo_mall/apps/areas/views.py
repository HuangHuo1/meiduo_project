from django import http
from django.core.cache import cache

from django.shortcuts import render

# Create your views here.
from django.views import View

from areas.models import Area
from meiduo_mall.utils.response_code import RETCODE
from users.utils import LoginRequiredMixin


class SubAreasView(View):
    def get(self, request, pk):
        """子级地区：市和县

        #1查询市或区数据
        #2序列化市，或区数据
        #3响应
        #补充缓存数据
        """
        # 判断是否有缓存
        sub_data = cache.get('sub_area_' + pk)

        # 1查询市或区数据
        try:
            sud_model_list = Area.objects.filter(parent=pk)
            parent_model = Area.objects.get(id=pk)
            # 整理市或区数据
            sub_list = []
            for sub_model in sud_model_list:
                sub_list.append({'id': sub_model.id,
                                 'name': sub_model.name})

                sub_data = {
                    'id': parent_model.id,
                    'name': parent_model.name,
                    'subs': sub_list
                }
                #缓存数据
                cache.set('sub_area_' + pk,sub_data,3600)
        except Exception as  f:
            return http.JsonResponse({'code': RETCODE.DBERR,
                                      'errmsg': '城市或区县数据错误',
                                      })
        #响应市或区的数据
        return http.JsonResponse({'code':RETCODE.OK,
                                  'errmsg':'ok',
                                  'sub_data':sub_data})


class ProvinceAreasView(View):
    """
    省级地区
    """

    def get(self, request):
        """
        提供省级地区数据
        :param request:
        :return:
        """
        # 1,查询省级数据
        # 2序列化省级数据
        # 3响应省级数据
        # 4补充缓存逻辑
        # 判断是否有缓存
        province_list = cache.get

        # 1,查询省级数据
        try:
            province_model_list = Area.objects.filter(parent__isnull=True)
            # 2整理省级数据
            province_list = []
            for i in province_model_list:
                province_list.append({'id': i.id,
                                      'name': i.name})
                cache.set('province_list', province_list, 3600)
        except Exception as f:
            return http.JsonResponse({'code': RETCODE.DBERR,
                                      'errmsg': '省份数据错误'})

        return http.JsonResponse({'code': RETCODE.OK,
                                  'errmsg': 'ok',
                                  'province_list': province_list})

class AddressView(LoginRequiredMixin,View):
    """
    用户收货地址
    """
    def get(self,request):
        """地址页面接口"""
        return render(request,'user_center_site.html')
