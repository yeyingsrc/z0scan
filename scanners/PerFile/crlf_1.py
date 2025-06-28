#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/16

import re
import copy, random, string
from api import generateResponse, VulType, PLACE, Type, PluginBase, conf, Threads

class Z0SCAN(PluginBase):
    name = "crlf_1"
    desc = 'CRLF Injection'
    version = "2025.6.16"
    risk = 2

    def _check_response(self, resp, test_header):
        if test_header['header_name'] in resp.headers:
            return True, "headers"
        body_pattern = re.compile(
            rf"{test_header['header_name']}\s*:\s*{test_header['header_value']}", 
            re.I | re.M
        )
        if body_pattern.search(resp.text):
            return True, "body"
        return False, None

    def audit(self):
        if conf.level == 0 or not 2 in conf.risk or self.fingerprints.waf:
            return
        _payloads = [
            # 基础换行组合
            f"\\r\\n\\t",
            "%0a%0a", 
        ]
        if conf.level >= 2:
            _payloads += [
                '%250a', 
                "čĊ", # Node.js风格  
                '%3f%23%0d%0a%09', 
                '%25%30%61', 
            ]
        if conf.level == 3:
            _payloads += [
                "%0d%0a", 
                '%3f', 
                "嘊嘍",    # Twitter风格
                '%u000d%u000a', # UNICODE
                '%25250a', # 三次URL编码
            ]
        rand_str = ''.join(random.choices(string.hexdigits, k=6)).lower()
        test_header = {
            'header_name': f"X-{rand_str}",
            'header_value': f"{rand_str}"
        }
        iterdatas = self.generateItemdatas()
        z0thread = Threads(name="crlf_1")
        z0thread.submit(self.process, iterdatas, _payloads, test_header)
            
    def process(self, _, _payloads, test_header):
        k, v, position = _
        if position in [PLACE.JSON_DATA, PLACE.XML_DATA, PLACE.MULTIPART_DATA, PLACE.ARRAY_LIKE_DATA, PLACE.SOAP_DATA]:
            return
        for _payload in _payloads:
            _payload = f"{_payload}{test_header['header_name']}: {test_header['header_value']}"
            payload = self.insertPayload({
                "key": k,
                "position": position,
                "payload": _payload,
            })
            r = self.req(position, payload)
            is_vuln, location = self._check_response(r, test_header)
            if not is_vuln:
                continue
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST,
                "url": self.requests.url,
                "vultype": VulType.CRLF,
                "show": {
                    "Payload": payload
                }
            })
            result.step("Request1", {
                "request": r.reqinfo,
                "response": generateResponse(r),
                "desc": f"Find {test_header['header_name']} in {location}"
            })
            self.success(result)
            return