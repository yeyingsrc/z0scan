#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# 总配置

THREAD_NUM = 31  # 默认线程数量
EXCLUDES = ["google", '.gov.', 'baidu', 'firefox', 'microsoft.com', '.bing.', 'msn.cn']  # 排除包含关键字的网址
RETRY = 2  # 超时重试次数
TIMEOUT = 6  # 超时时间
LEVEL = 2 # 0:纯被动分析模式，不做额外请求 | 1:最低请求量的扫描，最低的业务影响 | 2:中等请求量的扫描，Payload多为通用Top3 | 3:大量请求扫描，Payload覆盖面更广
SKIP_WAF_RECHECK = True # 是否跳过曾经检测到WAF但在本次启动后的扫描中未检测的站点的WAF检测

# 下游代理配置

PROXY_CONFIG_BOOL = False
PROXY_CONFIG = {
    # "http": "127.0.0.1:8080",
    # "https": "127.0.0.1:8080"
}


# 插件配置

ABLE = []  # 允许使用的插件
DISABLE = []  # 不允许使用的插件
XSS_LIMIT_CONTENT_TYPE = True  # 限制xss的content-type，为True时限制content-type为html，为False不限制
SQLi_TIME = 4 # SQLi插件延时时间
PSEUDO_STATIC_KEYWORDS = ['id', 'pid', 'cid', 'user', 'page', 'category', 'column_id', 'tty'] # 伪静态SQL关键点参数（忽略大小写）


# 反连配置

USE_REVERSE = False  # 使用反连平台将False改为True
REVERSE_HTTP_IP = "127.0.0.1"  # 回连http IP地址，需要改为服务器ip，不能改为0.0.0.0，因为程序无法识别
REVERSE_HTTP_PORT = 9999  # 回连http端口
REVERSE_DNS = ""
REVERSE_RMI_IP = "127.0.0.1"  # Java RMI 回连IP,需要改为服务器ip，不能改为0.0.0.0，因为程序无法识别
REVERSE_RMI_PORT = 10002  # Java RMI 回连端口
REVERSE_SLEEP = 5  # 反连后延时检测时间，单位是(秒)
