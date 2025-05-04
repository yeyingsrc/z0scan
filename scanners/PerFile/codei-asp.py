#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/4
# JiuZero 2025/3/25

import random
from concurrent.futures import ThreadPoolExecutor, as_completed

from api import PluginBase, conf, ResultObject, VulType, generateResponse, Type, logger


class Z0SCAN(PluginBase):
    name = "codei-asp"
    desc = 'ASP Code Injection'

    def condition(self):
        for k, v in self.response.programing.items():
            if k == "ASP" and not self.response.waf:
                return True
        return False
        
    def audit(self):
        if self.condition():
            randint1 = random.randint(10000, 90000)
            randint2 = random.randint(10000, 90000)
            randint3 = randint1 * randint2
            _payloads = [
                'response.write({}*{})'.format(randint1, randint2),
                '\'+response.write({}*{})+\''.format(randint1, randint2),
                '"response.write({}*{})+"'.format(randint1, randint2),
            ]
            
            iterdatas = self.generateItemdatas()
            with ThreadPoolExecutor(max_workers=None) as executor:
                futures = [
                    executor.submit(self.process, _, _payloads, randint3) for _ in iterdatas
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
                    
    def process(self, _, _payloads, randint3):
        k, v, position = _
        for _payload in _payloads:
            payload = self.insertPayload(k, "", position, _payload)
            r = self.req(position, payload)
            if not r:
                continue
            html = r.text
            if str(randint3) in html:
                result = ResultObject(self)
                result.main(Type.REQUEST, self.requests.hostname, r.url, VulType.CODE_INNJECTION, position, param=k, payload=payload)
                result.step("Request", r.reqinfo, generateResponse(r), "Match Int {}".format(randint3))
                self.success(result)
                return True
    