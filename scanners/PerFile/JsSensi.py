#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/6
# JiuZero 2025/3/4

import re

from data.rule.JsSensitive import rules
from api import VulType, PLACE, Type, ResultObject, PluginBase, conf


class Z0SCAN(PluginBase):
    name = "JsSensi"
    desc = 'Js Sensitive Finder'

    def condition(self):
        if self.requests.suffix == ".js" and 0 in conf.level:
            return True
        return False
        
    def audit(self):
        if not self.condition():
            return
        for name, _ in rules.items():
            texts = re.findall(_, self.response.text, re.M | re.I)
            issuc = False
            if texts:
                for text in set(texts):
                    ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                    is_continue = True

                    for i in ignores:
                        if i in text:
                            is_continue = False
                            break
                    if not is_continue:
                        continue

                    result = ResultObject(self)
                    result.init_info(Type.ANALYZE, self.requests.hostname, self.requests.url, VulType.SENSITIVE, PLACE.URL, msg="From Regx {} Find Sensitive Info {}".format(_, text))
                    result.add_detail("Request", self.requests.raw, self.response.raw, "From Regx {} Find Sensitive Info {}".format(_, text))
                    self.success(result)
                    issuc = True
                    break
            if issuc:
                break
