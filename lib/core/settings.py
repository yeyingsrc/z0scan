#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero

from lib.core.log import colors

VERSION = '2025.4.13'
SITE = 'https://github.com/JiuZero/z0scan'
DEFAULT_USER_AGENT = "z0scan/#v%s (%s)" % (VERSION, SITE)

banner = r"""
{cy}__  _     __   _   _  _ _     
{cy} / (.\   (_ ` / ` /_) )\ )       {m}~ Z0SCAN : {b}v{v} ~
{cy}/_  \_) .__) (_. / / (  (.   {g}{s}{e}

""".format(s=SITE, v=VERSION, m=colors.m, cy=colors.cy, g=colors.g, b=colors.b, e=colors.e)

ignoreParams = ['submit', '_', '_t', 'rand', 'hash']

logoutParams = [
    'logout',
    'log_out',
    'loginesc',
    'loginout',
    'delete',
    'signout',
    'logoff',
    'signoff',
    'exit',
    'quit',
    'byebye',
    'bye-bye',
    'clearuser',
    'invalidate',
    'reboot',
    'shutdown',
]

# 默认的COOKIE参数划分字符
DEFAULT_COOKIE_DELIMITER = ';'

# 默认的GET/POST参数划分字符
DEFAULT_GET_POST_DELIMITER = '&'

# Regular expression used for detecting Array-like POST data
ARRAY_LIKE_RECOGNITION_REGEX = r"(\A|%s)(\w+)\[\]=.+%s\2\[\]=" % (
    DEFAULT_GET_POST_DELIMITER, DEFAULT_GET_POST_DELIMITER)

# XML POST数据的正则提取
XML_RECOGNITION_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

# Regular expression used for detecting JSON POST data
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression used for detecting JSON-like POST data
JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*'[^']+'\s*:\s*('[^']+'|\d+).*\}\s*(\]\s*)*\Z"

# Regular expression used for detecting multipart POST data
MULTIPART_RECOGNITION_REGEX = r"(?i)Content-Disposition:[^;]+;\s*name="

# 支持的文件后缀
acceptedExt = [
    '.php', '.php2', '.php3', '.php4', '.php5', '.phtml',
    '.asp', '.aspx', '.ascx', '.asmx',
    '.chm', '.cfc', '.cfmx', '.cfml',
    '.py',
    '.rb',
    '.pl',
    '.cgi',
    '.jsp', '.jhtml', '.jhtm', '.jws',
    '.htm', '.html',
    '.do', '.action', ''
]

# 不支持的文件后缀
notAcceptedExt = [
    ".css",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".wmv",
    ".a3c",
    ".ace",
    ".aif",
    ".aifc",
    ".aiff",
    ".arj",
    ".asf",
    ".asx",
    ".attach",
    ".au",
    ".avi",
    ".bin",
    ".bmp",
    ".cab",
    ".cache",
    ".class",
    ".djv",
    ".djvu",
    ".dwg",
    ".es",
    ".esl",
    ".exe",
    ".fif",
    ".fvi",
    ".gz",
    ".hqx",
    ".ice",
    ".ico",
    ".ief",
    ".ifs",
    ".iso",
    ".jar",
    ".jpe",
    ".kar",
    ".mdb",
    ".mid",
    ".midi",
    ".mov",
    ".movie",
    ".mp",
    ".mp2",
    ".mp3",
    ".mp4",
    ".mpeg",
    ".mpeg2",
    ".mpg",
    ".mpg2",
    ".mpga",
    ".msi",
    ".pac",
    ".pdf",
    ".ppt",
    ".psd",
    ".qt",
    ".ra",
    ".ram",
    ".rar",
    ".rm",
    ".rpm",
    ".snd",
    ".svf",
    ".tar",
    ".tgz",
    ".tif",
    ".tiff",
    ".tpl",
    ".ttf",
    ".uff",
    ".wav",
    ".wma",
    ".zip",
    ".woff2"
]

XSS_EVAL_ATTITUDES = ['onbeforeonload', 'onsubmit', 'ondragdrop', 'oncommand', 'onbeforeeditfocus', 'onkeypress',
                      'onoverflow', 'ontimeupdate', 'onreset', 'ondragstart', 'onpagehide', 'onunhandledrejection',
                      'oncopy',
                      'onwaiting', 'onselectstart', 'onplay', 'onpageshow', 'ontoggle', 'oncontextmenu', 'oncanplay',
                      'onbeforepaste', 'ongesturestart', 'onafterupdate', 'onsearch', 'onseeking',
                      'onanimationiteration',
                      'onbroadcast', 'oncellchange', 'onoffline', 'ondraggesture', 'onbeforeprint', 'onactivate',
                      'onbeforedeactivate', 'onhelp', 'ondrop', 'onrowenter', 'onpointercancel', 'onabort',
                      'onmouseup',
                      'onbeforeupdate', 'onchange', 'ondatasetcomplete', 'onanimationend', 'onpointerdown',
                      'onlostpointercapture', 'onanimationcancel', 'onreadystatechange', 'ontouchleave',
                      'onloadstart',
                      'ondrag', 'ontransitioncancel', 'ondragleave', 'onbeforecut', 'onpopuphiding', 'onprogress',
                      'ongotpointercapture', 'onfocusout', 'ontouchend', 'onresize', 'ononline', 'onclick',
                      'ondataavailable', 'onformchange', 'onredo', 'ondragend', 'onfocusin', 'onundo', 'onrowexit',
                      'onstalled', 'oninput', 'onmousewheel', 'onforminput', 'onselect', 'onpointerleave', 'onstop',
                      'ontouchenter', 'onsuspend', 'onoverflowchanged', 'onunload', 'onmouseleave',
                      'onanimationstart',
                      'onstorage', 'onpopstate', 'onmouseout', 'ontransitionrun', 'onauxclick', 'onpointerenter',
                      'onkeydown', 'onseeked', 'onemptied', 'onpointerup', 'onpaste', 'ongestureend', 'oninvalid',
                      'ondragenter', 'onfinish', 'oncut', 'onhashchange', 'ontouchcancel', 'onbeforeactivate',
                      'onafterprint', 'oncanplaythrough', 'onhaschange', 'onscroll', 'onended', 'onloadedmetadata',
                      'ontouchmove', 'onmouseover', 'onbeforeunload', 'onloadend', 'ondragover', 'onkeyup',
                      'onmessage',
                      'onpopuphidden', 'onbeforecopy', 'onclose', 'onvolumechange', 'onpropertychange', 'ondblclick',
                      'onmousedown', 'onrowinserted', 'onpopupshowing', 'oncommandupdate', 'onerrorupdate',
                      'onpopupshown',
                      'ondurationchange', 'onbounce', 'onerror', 'onend', 'onblur', 'onfilterchange', 'onload',
                      'onstart',
                      'onunderflow', 'ondragexit', 'ontransitionend', 'ondeactivate', 'ontouchstart', 'onpointerout',
                      'onpointermove', 'onwheel', 'onpointerover', 'onloadeddata', 'onpause', 'onrepeat',
                      'onmouseenter',
                      'ondatasetchanged', 'onbegin', 'onmousemove', 'onratechange', 'ongesturechange',
                      'onlosecapture',
                      'onplaying', 'onfocus', 'onrowsdelete']

TOP_RISK_GET_PARAMS = {"id", 'action', 'type', 'm', 'callback', 'cb'}