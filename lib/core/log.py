#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/24
 
from colorama import Fore, Style
import time, os, sys
from lib.core.data import conf

def dataToStdout(data, bold=False):
    os.write(sys.stdout.fileno(), data.encode())
    return

class colors:
    r = Fore.RED
    b = Fore.BLUE
    m = Fore.MAGENTA
    cy = Fore.CYAN
    g = Fore.GREEN
    y = Fore.YELLOW
    e = Style.RESET_ALL
    
class logger:
    @staticmethod
    def _get_time():
        return time.strftime('%H:%M:%S', time.localtime(time.time()))
 
    @staticmethod
    def warning(value):
        _time = logger._get_time()
        dataToStdout(
            "[{}{}{}] [{}WARN{}] {}\n".format(colors.b, _time, colors.e, colors.y, colors.e, value)
        )
 
    @staticmethod
    def error(value, origin=None):
        _time = logger._get_time()
        if origin:
            dataToStdout(
                "[{}{}{}] [{}ERROR{}] [{}{}{}] {}\n".format(colors.b, _time, colors.e, colors.r, colors.e, colors.cy, origin, colors.e, value)
            )
        else:
            dataToStdout(
                "[{}{}{}] [{}ERROR{}] {}\n".format(colors.b, _time, colors.e, colors.r, colors.e, value)
            )
 
    @staticmethod
    def info(value):
        _time = logger._get_time()
        dataToStdout(
            "[{}{}{}] [{}INFO{}] {}\n".format(colors.b, _time, colors.e, colors.g, colors.e, value)
        )
 
    @staticmethod
    def debug(value, origin=None):
        if conf.debug:
            _time = logger._get_time()
            if origin:
                dataToStdout(
                    "[{}{}{}] [{}DEBUG{}] [{}{}{}] {}\n".format(colors.b, _time, colors.e, colors.m, colors.e, colors.cy, origin, colors.e, value)
                )
            else:
                dataToStdout(
                    "[{}{}{}] [{}DEBUG{}] {}\n".format(colors.b, _time, colors.e, colors.m, colors.e, value)
                )
