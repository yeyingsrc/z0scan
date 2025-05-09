#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

import requests
from urllib.parse import urlparse

from api import generateResponse, VulType, PLACE, HTTPMETHOD, ResultObject, PluginBase, KB, Type


class Z0SCAN(PluginBase):
    name = "crlf-nginx"
    desc = 'NGINX CRLF'

    def __init__(self):
        super().__init__()
        self.clrf_path = r'/%0d%0aDetectify:%20clrf'
    
    def condition(self):
        for k, v in self.response.webserver.items():
            if k == "NGINX":
                return True
        return False
        
    def audit(self):
        if self.condition():
            r = requests.get(self.requests.netloc + self.clrf_path, verify=False)
            if "Detectify" in r.headers:
                result = self.generate_result()
                result.main(Type.Request, self.requests.hostname, r.url, VulType.CRLF, PLACE.URL)
                result.step("Request", r.reqinfo, generateResponse(r), "Match Keyword: Detectify")
                self.success(result)