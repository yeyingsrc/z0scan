#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/3/4

import copy
import requests
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib.core.common import get_middle_text, generateResponse
from api import conf, HTTPMETHOD, PLACE, VulType, Type, PluginBase, logger


class Z0SCAN(PluginBase):
    name = "sensi-php-realpath"
    desc = 'Php Real Path Finder'
    
    def condition(self):
        for k, v in self.response.programing.items():
            if k == "PHP":
                return True
        return False
        
    def audit(self):
        if self.condition():
            headers = deepcopy(self.requests.headers)
            iterdatas = self.generateItemdatas()
            with ThreadPoolExecutor(max_workers=None) as executor:
                futures = [
                    executor.submit(self.process, _) for _ in iterdatas
                ]
                try:
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as task_e:
                            logger.error(f"Task failed: {task_e}", origin=self.name)
                except KeyboardInterrupt:
                    executor.shutdown(wait=False)
                except Exception as e:
                    logger.error(f"Unexpected error: {e}", origin=self.name)
                    executor.shutdown(wait=False)
                    
    def process(self, _):
        k, v, position = _
        _k = k + "[]"
        payload = self.insertPayload(_k, v, position, "")
        r = self.req(position, payload)
        if "Warning" in r.text and "array given in " in r.text:
            path = get_middle_text(r.text, 'array given in ', ' on line')
            result = self.generate_result()
            result.main(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SENSITIVE, position, msg="PATH Sensitive {p}".format(p=path), param=_k)
            result.step("Request", r.reqinfo, generateResponse(r), "")
            self.success(result)
            return True
