#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/28
# JiuZero 2025/3/24

import base64, copy, hashlib, json, os, random, re, string, struct, requests, sys, socket, ipaddress
from urllib.parse import urlparse, urljoin, quote, urlunparse
from colorama.ansi import code_to_chars
from lib.core.enums import PLACE, POST_HINT
from lib.core.settings import DEFAULT_GET_POST_DELIMITER, DEFAULT_COOKIE_DELIMITER
from fake_useragent import UserAgent
from lib.core.data import conf

def getmd5(s):
    m = hashlib.md5()
    if not isinstance(s, str):
        s = str(s)
    b = s.encode(encoding='utf-8')
    m.update(b)
    return m.hexdigest()

def is_ipaddr(host):
    try:
        ipaddress.ip_address(str(host))
        return True
    except Exception as ex:
        return False

def random_headers():
    HEADERS = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': "",
        'Referer': "",
        'X-Forwarded-For': "",
        'X-Real-IP': "",
        'Connection': 'keep-alive',
    }
    ua = UserAgent()
    key = random.random() * 20
    referer = ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(int(key))])
    referer = 'www.' + referer.lower() + '.com'
    ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    HEADERS["User-Agent"] = ua.random
    HEADERS["Referer"] = referer
    HEADERS["X-Forwarded-For"] = HEADERS["X-Real-IP"] = ip
    return HEADERS

def get_parent_paths(path, domain=True):
    '''
    通过一个链接分离出各种目录
    :param path:
    :param domain:
    :return:
    '''
    netloc = ''
    if domain:
        p = urlparse(path)
        path = p.path
        netloc = "{}://{}".format(p.scheme, p.netloc)
    paths = []
    if not path or path[0] != '/':
        return paths
    # paths.append(path)
    if path[-1] == '/':
        paths.append(netloc + path)
    tph = path
    if path[-1] == '/':
        tph = path[:-1]
    while tph:
        tph = tph[:tph.rfind('/') + 1]
        paths.append(netloc + tph)
        tph = tph[:-1]
    return paths


def get_links(content, domain, limit=True):
    '''
    从网页源码中匹配链接
    :param content: html源码
    :param domain: 当前网址domain
    :param limit: 是否限定于此域名
    :return:
    '''
    p = urlparse(domain)
    netloc = "{}://{}{}".format(p.scheme, p.netloc, p.path)
    match = re.findall(r'''(href|src)=["'](.*?)["']''', content, re.S | re.I)
    urls = []
    for i in match:
        _domain = urljoin(netloc, i[1])
        if limit:
            if p.netloc.split(":")[0] not in _domain:
                continue
        urls.append(_domain)
    return urls


def random_str(length=10, chars=string.ascii_lowercase):
    return ''.join(random.sample(chars, length))


def random_num(nums):
    return int(random_str(length=int(nums), chars=string.digits))


def random_UA():
    agents = conf.lists["_agents"]
    return str(agents[random.randint(0, len(agents) - 1)])


def md5(src):
    m2 = hashlib.md5()
    m2.update(src)
    return m2.hexdigest()


def get_middle_text(text, prefix, suffix, index=0):
    """
    获取中间文本的简单实现

    :param text:要获取的全文本
    :param prefix:要获取文本的前部分
    :param suffix:要获取文本的后半部分
    :param index:从哪个位置获取
    :return:
    """
    try:
        index_1 = text.index(prefix, index)
        index_2 = text.index(suffix, index_1 + len(prefix))
    except ValueError:
        # logger.log(CUSTOM_LOGGING.ERROR, "text not found pro:{} suffix:{}".format(prefix, suffix))
        return ''
    return text[index_1 + len(prefix):index_2]


def prepare_url(url, params):
    req = requests.Request('GET', url, params=params)
    r = req.prepare()
    return r.url


def paramToDict(parameters, place=PLACE.PARAM, hint=POST_HINT.NORMAL) -> dict:
    """
    Split the parameters into names and values, check if these parameters
    are within the testable parameters and return in a dictionary.
    """

    testableParameters = {}
    if place == PLACE.COOKIE:
        splitParams = parameters.split(DEFAULT_COOKIE_DELIMITER)
        for element in splitParams:
            parts = element.split("=")
            if len(parts) >= 2:
                testableParameters[parts[0]] = ''.join(parts[1:])
    elif place == PLACE.PARAM:
        splitParams = parameters.split(DEFAULT_GET_POST_DELIMITER)
        for element in splitParams:
            parts = element.split("=")
            if len(parts) >= 2:
                testableParameters[parts[0]] = ''.join(parts[1:])
    elif place == PLACE.NORMAL_DATA:
        if hint == POST_HINT.NORMAL:
            splitParams = parameters.split(DEFAULT_GET_POST_DELIMITER)
            for element in splitParams:
                parts = element.split("=")
                if len(parts) >= 2:
                    testableParameters[parts[0]] = ''.join(parts[1:])
        elif hint == POST_HINT.ARRAY_LIKE:
            splitParams = parameters.split(DEFAULT_GET_POST_DELIMITER)
            for element in splitParams:
                parts = element.split("=")
                if len(parts) >= 2:
                    key = parts[0]
                    value = ''.join(parts[1:])
                    if '[' in key:
                        if key not in testableParameters:
                            testableParameters[key] = []
                        testableParameters[key].append(value)
                    else:
                        testableParameters[key] = value
        elif hint == POST_HINT.JSON:
            try:
                testableParameters = json.loads(parameters)
            except json.JSONDecodeError:
                testableParameters = {}
    return testableParameters


def isListLike(value):
    """
    Returns True if the given value is a list-like instance

    >>> isListLike([1, 2, 3])
    True
    >>> isListLike('2')
    False
    """

    return isinstance(value, (list, tuple, set))


def findMultipartPostBoundary(post):
    """
    Finds value for a boundary parameter in given multipart POST body

    >>> findMultipartPostBoundary("-----------------------------9051914041544843365972754266\\nContent-Disposition: form-data; name=text\\n\\ndefault")
    '9051914041544843365972754266'
    """

    retVal = None

    done = set()
    candidates = []

    for match in re.finditer(r"(?m)^--(.+?)(--)?$", post or ""):
        _ = match.group(1).strip().strip('-')

        if _ in done:
            continue
        else:
            candidates.append((post.count(_), _))
            done.add(_)

    if candidates:
        candidates.sort(key=lambda _: _[0], reverse=True)
        retVal = candidates[0][1]

    return retVal


def generateResponse(resp: requests.Response):
    response_raw = "HTTP/1.1 {} {}\r\n".format(resp.status_code, resp.reason)
    for k, v in resp.headers.items():
        response_raw += "{}: {}\r\n".format(k, v)
    response_raw += "\r\n"
    response_raw += resp.text
    return response_raw


def ltrim(text, left):
    num = len(left)
    if text[0:num] == left:
        return text[num:]
    return text


def splitUrlPath(url, all_replace=True, flag='<--flag-->') -> list:
    ''''
    all_replace 默认为True 替换所有路径，False 在路径后面加
    falg 要加入的标记符
    '''
    u = urlparse(url)
    path_split = u.path.split("/")[1:]
    path_split2 = []
    for i in path_split:
        if i.strip() == "":
            continue
        path_split2.append(i)

    index = 0
    result = []

    for path in path_split2:
        copy_path_split = copy.deepcopy(path_split2)
        if all_replace:
            copy_path_split[index] = flag
        else:
            copy_path_split[index] = path + flag

        new_url = urlunparse([u.scheme, u.netloc,
                              ('/' + '/'.join(copy_path_split)),
                              u.params, u.query, u.fragment])
        result.append(new_url)
        sptext = os.path.splitext(path)
        if sptext[1]:
            if all_replace:
                copy_path_split[index] = flag + sptext[1]
            else:
                copy_path_split[index] = sptext[0] + flag + sptext[1]
            new_url = urlunparse([u.scheme, u.netloc,
                                  ('/' + '/'.join(copy_path_split)),
                                  u.params, u.query, u.fragment])
            result.append(new_url)
        index += 1

    return result


def url_dict2str(d: dict, position=PLACE.PARAM):
    if isinstance(d, str):
        return d
    temp = ""
    urlsafe = "!$%'()*+,/:;=@[]~"
    if position == PLACE.PARAM or position == PLACE.NORMAL_DATA:
        for k, v in d.items():
            temp += "{}={}{}".format(k, quote(v, safe=urlsafe), DEFAULT_GET_POST_DELIMITER)
        temp = temp.rstrip(DEFAULT_GET_POST_DELIMITER)
    elif position == PLACE.COOKIE:
        for k, v in d.items():
            temp += "{}={}{} ".format(k, quote(v, safe=urlsafe), DEFAULT_COOKIE_DELIMITER)
        temp = temp.rstrip(DEFAULT_COOKIE_DELIMITER)
    return temp
