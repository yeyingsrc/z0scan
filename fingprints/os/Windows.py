#!/usr/bin/env python 
# -*- coding:utf-8 -*-
# @name:    Windows Server

from re import search, I, compile, error

from lib.core.enums import OS


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

keys = [ r"Win32|Win64", r"WinCE" ]

def fingerprint(headers, content):
    _ = False
    if 'server' in headers.keys():
        for _ in keys:
            if search(_, headers["server"], I): return "WINDOWS", None
    return None, None
