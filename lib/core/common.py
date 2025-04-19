#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/28
# JiuZero 2025/3/24

import base64, copy, hashlib, json, os, random, re, string #sys
from urllib.parse import urlparse, urljoin, quote, urlunparse
import requests, sys
from colorama.ansi import code_to_chars

from lib.core.enums import PLACE, POST_HINT
from lib.core.settings import DEFAULT_GET_POST_DELIMITER, DEFAULT_COOKIE_DELIMITER

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
    ua_list = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.122',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71',
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)',
        'Mozilla/5.0 (Windows NT 5.1; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.50',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 '
        'Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/76.0.3809.100 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/68.0',
        'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0',
    ]
    return random.choice(ua_list)


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
    if place == PLACE.HEADER:
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
    elif place == PLACE.DATA:
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
    if position == PLACE.PARAM or position == PLACE.DATA:
        for k, v in d.items():
            temp += "{}={}{}".format(k, quote(v, safe=urlsafe), DEFAULT_GET_POST_DELIMITER)
        temp = temp.rstrip(DEFAULT_GET_POST_DELIMITER)
    elif position == PLACE.HEADER:
        for k, v in d.items():
            temp += "{}={}{} ".format(k, quote(v, safe=urlsafe), DEFAULT_COOKIE_DELIMITER)
        temp = temp.rstrip(DEFAULT_COOKIE_DELIMITER)
    return temp


def updateJsonObjectFromStr(base_obj, update_str: str):
    assert (type(base_obj) in (list, dict))
    base_obj = copy.deepcopy(base_obj)
    # 存储上一个value是str的对象，为的是更新当前值之前，将上一个值还原
    last_obj = None
    # 如果last_obj是dict，则为字符串，如果是list，则为int，为的是last_obj[last_key]执行合法
    last_key = None
    last_value = None
    # 存储当前层的对象，只有list或者dict类型的对象，才会被添加进来
    curr_list = [base_obj]
    # 只要当前层还存在dict或list类型的对象，就会一直循环下去
    while len(curr_list) > 0:
        # 用于临时存储当前层的子层的list和dict对象，用来替换下一轮的当前层
        tmp_list = []
        for obj in curr_list:
            # 对于字典的情况
            if type(obj) is dict:
                for k, v in obj.items():
                    # 如果不是list, dict, str类型，直接跳过
                    if type(v) not in (list, dict, str, int):
                        continue
                    # list, dict类型，直接存储，放到下一轮
                    if type(v) in (list, dict):
                        tmp_list.append(v)
                    # 字符串类型的处理
                    else:
                        # 如果上一个对象不是None的，先更新回上个对象的值
                        if last_obj is not None:
                            last_obj[last_key] = last_value
                        # 重新绑定上一个对象的信息
                        last_obj = obj
                        last_key, last_value = k, v
                        # 执行更新
                        obj[k] = update_str
                        # 生成器的形式，返回整个字典
                        yield base_obj

            # 列表类型和字典差不多
            elif type(obj) is list:
                for i in range(len(obj)):
                    # 为了和字典的逻辑统一，也写成k，v的形式，下面就和字典的逻辑一样了，可以把下面的逻辑抽象成函数
                    k, v = i, obj[i]
                    if type(v) not in (list, dict, str, int):
                        continue
                    if type(v) in (list, dict):
                        tmp_list.append(v)
                    else:
                        if last_obj is not None:
                            last_obj[last_key] = last_value
                        last_obj = obj
                        last_key, last_value = k, v
                        obj[k] = update_str
                        yield base_obj
        curr_list = tmp_list
