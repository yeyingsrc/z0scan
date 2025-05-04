#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/7/23
# JiuZero 2025/3/2

import copy
import requests
from lib.core.option import init
from lib.helper.function import isJavaObjectDeserialization, isPHPObjectDeserialization, isPythonObjectDeserialization
from lib.core.plugins import PluginBase
from lib.core.output import ResultObject
from lib.core.enums import PLACE, HTTPMETHOD, VulType, Type, POST_HINT
from lib.core.data import conf, KB, path
from lib.core.log import logger
from lib.core.common import generateResponse, random_str, random_num, md5, updateJsonObjectFromStr, splitUrlPath, url_dict2str
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp
from lib.controller.controller import task_push_from_name, task_push, start
from z0scan import modulePath


__all__ = [
    'isJavaObjectDeserialization', 'isPHPObjectDeserialization', 'isPythonObjectDeserialization', 'updateJsonObjectFromStr', 
    'PluginBase', 'ResultObject', 'conf', 'KB', 'md5', 'updateJsonObjectFromStr', 'splitUrlPath', 'url_dict2str', 
    'path', 'logger', 'PLACE', 'HTTPMETHOD', 'VulType', 'generateResponse', 'task_push_from_name', 'task_push', 'random_str', 'start', 'Type',
    'random_num', 'OS', 'POST_HINT'
]


def scan(url, module_name, conf={}, headers={}):
    root = modulePath()
    cmdline = {
        "level": 4
    }
    cmdline.update(conf)
    init(root, cmdline)
    r = requests.get(url, headers=headers)
    req = FakeReq(url, headers, HTTPMETHOD.GET)
    resp = FakeResp(r.status_code, r.content, r.headers)
    poc_module = copy.deepcopy(KB["registered"][module_name])
    poc_module.execute(req, resp)