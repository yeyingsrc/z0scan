#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

import requests
from urllib.parse import urlparse

from api import generateResponse, VulType, PLACE, HTTPMETHOD, PluginBase, conf, KB, Type


class Z0SCAN(PluginBase):
    name = "other-nginx-clearcache"
    desc = 'Nginx Webcache Clear'
        
    def condition(self):
        for k, v in self.response.webserver.items():
            if k == "NGINX":
                return True
        return False
        
    def audit(self):
        if self.condition():
            r = requests.request("PURGE", self.requests.netloc + "/*", allow_redirects=True, verify=False)
            if r.status_code == 204:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.SENSITIVE
                    })
                result.step("Request1", {
                    "requests": r.reqinfo, 
                    "respomse": generateResponse(r), 
                    "desc": "Status Code is 204"
                    })
                self.success(result)