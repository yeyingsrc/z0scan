#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/18

import re
import random
from api import generateResponse, VulType, Type, PluginBase, KB, conf, Threads

class Z0SCAN(PluginBase):
    name = "xpathi-error"
    desc = 'XPath Injection'
    version = "2025.3.18"
    risk = 2

    def _detect_errors(self, response_text):
        error_patterns = {
            'exact': [
                'MS.Internal.Xml.',
                'org.apache.xpath.XPath',
                'Expression must evaluate to a node-set',
                'System.Xml.XPath.XPathException',
                'javax.xml.xpath.XPathException',
                'XPath evaluation exception',
                'Invalid XPath expression',
                'Failed to evaluate XPath expression',
            ],
            'regex': [
                r"XPath(?:EvalError|Syntax\s+Error|Compile\s+Error|Syntax\s+Error|Compile\s+Error)\b",
                r"XPath(?:Exception|Error|EvalError|EvalException):\s*['\"](?P<detail>.+?)['\"]",
                r"XPath\s+[Ee]rror\s*:\s*(?P<detail>.+?)(?:\n|$)",
                r"XPathEvalError:\s*(?P<detail>.+?)(?:\n|$)",
                r"Line\s+\d+:\s*(?:Invalid|Illegal)\s+XPath\s+expression",
                r"XPath\s+expression\s+error\s+at\s+line\s+(?P<line>\d+)",
                r"at\s+(org\.apache\.xpath|javax\.xml\.xpath|System\.Xml\.XPath|MS\.Internal\.Xml)",
                r"in\s+[^\s]+\.XPath(?:Exception|Evaluator|Compiler)",
                r"File\s+\".*?xpath.*?\.pxi\",\s+line\s+\d+",
                r"Error\s+code:\s+0x[0-9a-fA-F]+\s*\(XPath\)",
                r"XPath\s+error\s+code\s+\d+",
                r"XPath\s+syntax\s+error\s*(?:[:]\s*(?P<detail>.+?))?(?:\n|$)",
                r"Invalid\s+XPath\s+syntax\s+near\s+['\"](?P<token>.+?)['\"]",
                r"XPath\s+query\s+failed:\s*(?P<detail>.+?)(?:\n|$)",
                r"Failed\s+to\s+execute\s+XPath:\s*(?P<detail>.+?)(?:\n|$)"
            ]
        }
        if not response_text:
            return False, None
        # 精确匹配
        for pattern in error_patterns['exact']:
            if pattern in response_text:
                return True, f"Exact Match {pattern}"
        # 正则匹配
        for regex in error_patterns['regex']:
            match = re.search(regex, response_text, re.I)
            if match:
                detail = match.groupdict().get('detail', match.group(0))
                return True, f"Regex Match {detail}"
        return False, None

    def audit(self):
        if conf.level == 0 or not 2 in conf.risk or self.fingerprints.waf:
            return
        iterdatas = self.generateItemdatas()
        z0thread = Threads(name="xpathi-error")
        z0thread.submit(self.process, iterdatas)
                
    def process(self, _):
        k, v, position = _
        rand_num = random.randint(1000, 9999)
        _payloads = [
            # 基础闭合测试
            "\"')", "<!--",
            # 特殊字符组合
            "]]>", "*/*", "]["
        ]
        if conf.level == 3:
            _payloads += [
                # 错误诱导
                f"convert({rand_num}, 'invalid_type')",
            ]
        for _payload in _payloads:
            payload = self.insertPayload({
                "key": k, 
                "value": v, 
                "position": position, 
                "payload": _payload
                })
            r = self.req(position, payload)
            if not r.text:
                continue
            is_vuln, error_info = self._detect_errors(r.text)
            if is_vuln:
                result = self.generate_result()
                result.main({
                    "type": Type.REQUEST, 
                    "url": self.requests.url, 
                    "vultype": VulType.OTHER, 
                    "show": {
                        "Position": f"{position} >> {k}",
                        "Payload": payload
                        }
                    })
                result.step("Request1", {
                    "request": r.reqinfo, 
                    "response": generateResponse(r), 
                    "desc": f"{error_info}"
                    })
                self.success(result)
                return