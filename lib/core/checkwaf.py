#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# JiuZero  2025/3/25

from lib.core.data import conf, KB
from lib.core.log import logger, colors
from lib.core.db import insertdb, selectdb
from data.rule.waf import rules
from config import SKIP_WAF_RECHECK
import requests, random, string, difflib, re
from urllib.parse import quote

def CheckWaf(self):
    KB.limit = True

    where = "HOSTNAME='{}'".format(self.requests.hostname)
    history1 = selectdb("WAFHISTORY", "WAFNAME", where=where)
    where = "HOSTNAME='{}'".format(self.requests.hostname)
    history2 = selectdb("CACHE", "HOSTNAME", where=where)
    
    # 存在WAF且本次启动后有检测过
    if history1 and history2:
        self.response.waf = str(history1[0])
        return
    # 不存在WAF且本次启动后有检测过
    elif not history1 and history2:
        self.response.waf = None
        return
    # 存在WAF但本次启动后没有检测过
    elif history1 and not history2:
        if SKIP_WAF_RECHECK:
            self.response.waf = str(history1[0])
            return
    # 不存在WAF但本次启动后没有检测（未知情况）
    rand_param = '/?' + ''.join(random.choices(string.ascii_lowercase, k=4)) + '='
    payload = "UNION ALL SELECT 1,'<script>alert(\"XSS\")</script>' FROM information_schema WHERE --/**/ EXEC xp_cmdshell('cat ../../../etc/passwd')#"
    try:
        r1 = requests.get(self.requests.netloc, timeout=conf.timeout)
        r2 = requests.get(self.requests.netloc + rand_param + quote(payload), timeout=conf.timeout)
    # 超时与连接问题很可能产生于WAF
    except (TimeoutError, ConnectionError, Exception) as e:
        raise
        deal(self, True)
        return
    # 尝试指纹匹配
    for i in rules:
        name, method, position, regex = i.split('|')
        if method == 'headers':
            if self.requests.headers is not None:
                if re.search(regex, str(self.requests.headers.get(position))) is not None:
                    logger.warning("<{}{}{}> Protected by {}".format(colors.m, self.requests.hostname, colors.e, name))
                    self.response.waf = name
                    return
        else:
            if re.search(regex, str(self.requests.raw)):
                logger.warning("<{}{}{}> Protected by {}".format(colors.m, self.requests.hostname, colors.e, name))
                self.response.waf = name
                return
    # 页面相似度判断
    similarity = difflib.SequenceMatcher(r1, r2).ratio()
    if similarity < 0.5:
        print(1)
        deal(self, True)
        return
    else:
        print(2)
        deal(self, False)


def deal(self, state):
    if state:
        logger.warning("<{}{}{}> Protected by some kind of WAF/IPS".format(colors.m, self.requests.hostname, colors.e))
        self.response.waf = "UNKNOW"
        cv = {"HOSTNAME": self.requests.hostname,
              "WAFNAME": "UNKNOW"}
        insertdb("WAFHISTORY", cv)
        return
    else:
        self.response.waf = None
        return