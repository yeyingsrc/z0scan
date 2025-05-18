#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

import requests
from urllib.parse import urlparse

from api import conf, KB, generateResponse, VulType, PLACE, HTTPMETHOD, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "sensi-nginx-readvar"
    desc = 'Nginx Variable Leakage'
    
    def condition(self):
        for k, v in self.response.webserver.items():
            if k == "NGINX":
                return True
        return False
        
    def audit(self):
        if self.condition():
            variable_leakage = r'/foo$http_referer'
            headers={"Referer": "bar"}
            r = requests.get(self.requests.netloc + variable_leakage, headers=headers, verify=False)
            if r.status_code == 204:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.netloc + variable_leakage, 
                    "vultype": VulType.SENSITIVE
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": "Status Code is 204"
                    })
                self.success(result)