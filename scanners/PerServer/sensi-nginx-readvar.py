#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

import requests
from urllib.parse import urlparse

from api import conf, KB, generateResponse, VulType, PLACE, HTTPMETHOD, Type, ResultObject, PluginBase


class Z0SCAN(PluginBase):
    name = "sensi-nginx-readvar"
    desc = 'Nginx Variable Leakage'

    def __init__(self):
        super().__init__()
        self.variable_leakage = r'/foo$http_referer'
    
    def condition(self):
        for k, v in self.response.webserver.items():
            if k == "NGINX":
                return True
        return False
        
    def audit(self):
        if self.condition():
            headers={"Referer": "bar"}
            r = requests.get(self.requests.netloc + self.variable_leakage, headers=headers, verify=False)
            if r.status_code == 204:
                result = self.generate_result()
                result.main(Type.Request, self.requests.hostname, r.url, VulType.SENSITIVE, PLACE.URL)
                result.step("Request", r.reqinfo, generateResponse(r), "Status Code is 204")
                self.success(result)