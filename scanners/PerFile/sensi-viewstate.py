#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 2025/5/2 JiuZero

from api import VulType, Type, PLACE, PluginBase, generateResponse
import base64
import re

class Z0SCAN(PluginBase):
    name = "sensi-viewstate"
    desc = "Check for unencrypted ASP.NET ViewState parameters"
    
    def find_viewstate(self):
        patterns = [
            re.compile(r'<input[^>]+__VIEWSTATE["\' ][^>]*value=["\']([^"\']+)', re.I),
            re.compile(r'<input[^>]+value=["\']([^"\']+)["\' ][^>]+__VIEWSTATE', re.I),
            re.compile(r'__VIEWSTATE=([A-Za-z0-9+/=]+)')
        ]
        found = []
        # 从响应体中匹配
        for pattern in patterns:
            found.extend(pattern.findall(self.response.text))
        # 从POST参数中获取
        if self.requests.post_data:
            found.extend(v for k, v in self.requests.post_data.items() if k.lower() == "__viewstate")
        return list(set(found))
    
    def audit(self):
        viewstate_list = self.find_viewstate()
        
        for vs_value in viewstate_list:
            try:
                decoded = base64.urlsafe_b64decode(vs_value + '=' * (4 - len(vs_value) % 4))
                decoded_str = decoded.decode('utf-8', errors='replace')
                
                if any(keyword in decoded_str for keyword in ("System.", "Microsoft", "Type")):
                    result = self.generate_result()
                    position = PLACE.DATA if self.requests.post_data else PLACE.PARAM
                    result.main(Type.ANALYZE, self.requests.hostname, self.requests.url, VulType.SENSITIVE, position, msg="ViewState does not have MAC validation enabled and contains sensitive information", param="__VIEWSTATE", payload=vs_value)
                    result.step("ViewState parameter detection", self.requests.raw, generateResponse(self.response), f"Decoded pattern: {decoded_str[:200]}... (Length: {len(decoded_str)})")
                    self.success(result)
                    return
            except Exception as e:
                continue