#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Evi1ran Jan 14, 2021
# JiuZero 2025/3/4

from copy import deepcopy
import difflib
from api import generateResponse, VulType, PLACE, PluginBase, Type
from concurrent.futures import ThreadPoolExecutor, as_completed

class Z0SCAN(PluginBase):
    name = "unauth"
    desc = 'Unauthorized'
    seqMatcher = difflib.SequenceMatcher(None)
    SIMILAR_MIN = 0.90

    def condition(self):
        for k, v in self.requests.headers.items():
            if k.lower() in ["cookie", "token", "auth"]:
                return True
        return False
            
    def audit(self):
        if not self.condition():
            return
        resp = self.response.text
        headers, k = self.del_cookie_token()
        r = self.req(PLACE.HEADER, headers)
        if not r:
            return
        min_len = min(len(resp), len(r.text))
        self.seqMatcher = difflib.SequenceMatcher(None, resp[:min_len], r.text[:min_len])
        ratio = round(self.seqMatcher.quick_ratio(), 3)
        if ratio > self.SIMILAR_MIN:
            result = self.generate_result()
            result.main(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.UNAUTH, PLACE.HEADER, msg="Delete {}".format(k))
            result.step("Request", r.reqinfo, generateResponse(r), "Delete {}".format(k))
            self.success(result)
            return

    def del_cookie_token(self):
        request_headers = deepcopy(self.requests.headers)
        for k, v in self.requests.headers.items():
            if k.lower() in ["cookie", "token", "auth"]:
                del request_headers[k]
                return request_headers, k