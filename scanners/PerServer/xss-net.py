#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay
# JiuZero 2025/3/3

from urllib.parse import urlparse
import requests

from api import conf, KB, random_str, generateResponse, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "xss-net"
    desc = '.NET XSS'
    def condition(self):
        if not self.response.waf:
            return True
        return False
        
    def audit(self):
        if self.condition():
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)

            payload = "(A({}))/".format(random_str(6))
            url = domain + payload

            req = requests.get(url, headers=self.requests.headers)
            if payload in req.text:
                new_payload = "(A(\"onerror='{}'{}))/".format(random_str(6), random_str(6))
                url2 = domain + new_payload
                req2 = requests.get(url2, headers=self.requests.headers)
                if new_payload in req2.text:
                    result = self.generate_result()
                    result.main(Type.Request, self.requests.hostname, "{} | {}".format(req.url, req2.url), VulType.XSS, PLACE.URL)
                    result.step("Request", req.reqinfo, generateResponse(req), "Payload:{} Display on the page".format(payload))
                    result.step("Request", req2.reqinfo, generateResponse(req2), "Payload:{} Display on the page".format(payload))
                    self.success(result)
