#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/14

import re
import random
from urllib.parse import urlparse, unquote
from api import generateResponse, VulType, PLACE, Type, PluginBase, conf, logger, Threads

class Z0SCAN(PluginBase):
    name = "redirect"
    desc = 'Open Redirect'
    version = "2025.6.14"
    risk = 1
    
    def __init__(self):
        super().__init__()
        self.test_domain = f"http://{random.randint(10000,99999)}.com"
    
    def _detect_redirect_type(self, response):
        redirect_patterns = {
            'header': r"^https?://([\w-]+\.)*{}".format(re.escape(urlparse(self.test_domain).netloc)),
            'meta': r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=.*{}'.format(re.escape(self.test_domain)),
            'javascript': r"(location|window\.location|document\.location)(\.href|\.replace|\.assign)?\s*=\s*['\"]?{}".format(re.escape(self.test_domain))
        }
        # 30x 头检测
        if 300 <= response.status_code < 400:
            if 'location' in response.headers:
                location = unquote(response.headers['location'])
                if urlparse(location).netloc.endswith(urlparse(self.test_domain).netloc):
                    return "HTTP Head", location
        # Meta Refresh检测
        if re.search(redirect_patterns['meta'], response.text, re.I|re.S):
            return "HTML Meta", None
        # JavaScript跳转检测
        for script in self._extract_scripts(response.text):
            if re.search(redirect_patterns['javascript'], script, re.I):
                return "JavaScript", script
        return None, None

    def _extract_scripts(self, html):
        scripts = []
        for match in re.finditer(r'<script\b[^>]*>(.*?)</script>', html, re.I|re.S):
            script_content = match.group(1)
            for line in script_content.split(';'):
                line = line.strip()
                if line:
                    scripts.append(line)
        return scripts

    def _is_redirect_param(self, value):
        patterns = [
            r'^https?://',  # 完整URL
            r'^//[\w.-]+/',  # 协议相对
            r'^/[^\s]{5,}',  # 长路径
            r'^[a-z]{2,}://?[\w]', # 伪协议
            r';\s*url=', # Meta跳转
            r'\.replace\(',  # JS方法
            r'%2f%2f[\w.-]+%2f' # URL编码
        ]
        return any(re.search(p, value, re.I) for p in patterns)

    def audit(self):
        if conf.level != 0 and 1 in conf.risk and self.response.status_code == 302:
            iterdatas = self.generateItemdatas()
            z0thread = Threads(name="redirect")
            z0thread.submit(self.process, iterdatas)
    
    def process(self, _):
        k, v, position = _
        if self._is_redirect_param(v) or conf.level == 3: # level==3 时全检测
            payload = self.insertPayload({
                "key": k, 
                "position": position, 
                "payload": self.test_domain
                })
            r = self.req(position, payload, allow_redirects=False)
            if not r:
                return
            vuln_type, evidence = self._detect_redirect_type(r)
            if not vuln_type:
                return
            result = self.generate_result()
            result.main({
                "type": Type.REQUEST, 
                "url": self.requests.url, 
                "vultype": VulType.REDIRECT, 
                "show": {
                    "Payload": payload, 
                    "Position": f"{position} >> {k}",
                    "Msg": f"{vuln_type}", 
                    }
                })
            result.step("Request1", {
                "request": r.reqinfo, 
                "response": generateResponse(r), 
                "desc": f"Match Keywords {evidence[:100] if evidence else ''}"
                })
            self.success(result)
            return True