#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/11
# JiuZero 2025/6/5

import re
from data.rule.phpinfo_sensi import rules

def get_phpinfo(html) -> list:
    ret = []
    for regx, msg in rules:
        r = re.search(regx, html, re.I | re.M | re.S)
        if r:
            if "{}" in msg:
                ret.append(msg.format(r.group(1)))
            else:
                ret.append(msg)
    return ret
