#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:    Tengine

from re import search, I, compile, error
from lib.core.common import md5
from api import KB

def _prepare_pattern(pattern):
    """
    Strip out key:value pairs from the pattern and compile the regular
    expression.
    """
    regex, _, rest = pattern.partition(r'\;')
    try:
        return compile(regex, I)
    except error as e:
        return compile(r'(?!x)x')


def fingerprint(headers, content):
    version = None
    _ = False
    if 'server' in headers.keys():
        _ = search(r"Tengine", headers["server"], I)

    if _:
        return "TENGINE", None
    return None, None


def fingerprint_assign(url, filter):
    if 'php' in filter:
        return url
    if not filter:
        return url
    return None


def fingerprint_url(url, resp=None):
    payload = url + "/robots.txt"
    resp = resp.get(payload).text
    if md5(resp) == "xxxxxxx" or "emlog" in resp:
        return {
            "name": "Emlog",
            "version": "5.3.1",
            "language": "PHP",
            "database": "mysql"
        }
