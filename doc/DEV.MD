# Scanner 编写

## 命名

插件名称按照以下命名规则命名：
```
漏洞类型(简写) + 中间件 + 简述
```
注：
如有多个中间件，则以下划线分隔，如`other-nginx_iis-parse`
中间件与简述至少选择其一
漏洞类型分类与简写形式见`api/VulType`部分


## 内置模块

### api:
| 名称 | 描述 | 使用 | 必选/可选 |
| --------- | -------- | --------- | -------- | 
| generateResponse | 用于报告中响应体的生成 | generateResponse(r) # r=request.get(…) | 必选 |
| random_num | 生成随机数
| random_str | 生成随机字符串
| VulType | 对漏洞类型的选定 | 见api/VulType | 必选 |
| Type | 对扫描类型的选定 | 见api/Type | 必选 |
| PluginBase | 被继承以获取关键数据 | class Z0SCAN(PluginBase) | 必选 |
| conf | 储存一些命令行参数值 | 主要使用level，见api/conf.level | 必选 |
| PLACE | 对漏洞注入点（请求中的可控点）的选定 | 见api/PLACE | 必选 |

- api/VulType:
（这里参考的EDUSRC的漏洞划分，但HQL注入划分为SQL注入）
| 名称 | 描述 | (插件命名)简写 |
| --------- | -------- | -------- |
| CMD_INNJECTION | 命令注入漏洞 | cmdi |
| CODE_INJECTION | 代码注入漏洞 | codei |
| XSS | XSS跨站脚本攻击 | xss |
| SQLI | SQL注入漏洞 | sqli |
| TRAVERSAL | 遍历漏洞 | trave |
| XXE | XML外部实体注入 | xxe |
| SSRF | 服务器端请求伪造 | ssrf |
| CSRF | CSRF | csrf |
| REDIRECT | 重定向漏洞 | redirect |
| CRLF | 换行注入 | crlf |
| SENSITIVE | 敏感信息泄露漏洞 | sensi |
| SSTI | 服务器端模板注入 | ssti |
| UNAUTH | 未授权访问 | unauth |
| FILEUPLOAD | 文件上传 | upload |
| CORS | CORS漏洞 | cors |
| OTHER | 其它漏洞 | other |

- api/Type :
| 名称 | 描述 |
| --------- | -------- |
| ANALYZE | 被动分析发现 |
| REQUEST | 主动请求发现 |

- api/conf.level :
扫描深度（反映请求量）
| 值 | 描述 |
| --------- | -------- |
| 0 | 纯被动分析模式，不做额外请求 |
| 1 | 最低请求量的扫描，最低的业务影响 |
| 2 | 中等请求量的扫描，Payload多为通用Top3 |
| 3 | 大量请求扫描，Payload覆盖面更广 |
注：level>=2时即使未识别到版本号仍继续测试漏洞

- api/PLACE :
| 名称 | 描述 |
| --------- | -------- |
| PARAM | URL后参数部分 |
| DATA | BODY中传递的参数 |
| COOKIE | COOKIE中传递的参数 |
| URL | URL路径（包括伪静态参数） |
| HEADER | HEADER头部 |

### lib.helper.comper/compver(min, version, max, include=True) :
include值为True时包括最大最小值比对（闭区间）
在范围内返回True，否False
```
>> compver("7.0.0", v, "7.5.1")
True # v = "7.2.7"
False # v = "7.8.1"
```


## 解析出的数据
注：继承PluginBase后读取

- self.fingerprints :
| 名称 | 类型 | 描述 |
| --------- | ------- | -------- | 
| os | dict | OS系统指纹 |
| webserver | dict | 中间件 |
| programing | dict | 项目类型 |
| waf | str | WAF名称（未检测到WAF时为None） |
对于`os、webserver、programing`：
```
>> print(self.fingerprints.programing)
{"PHP" : "1.9.6"} # 名称 : 版本信息
```

- self.requests :
| 名称 | 类型 | 描述 | 示例 |
| --------- | -------- | --------- | ------- |
| url | str  | 完整的URL（包含GET参数） | https://www.example.com:443/a/file.php?id=1 |
| raw  | str  | 完整的请求包 | / |
| method | str |  请求方法  | GET |
| suffix  | str | 文件后缀 | .php |
| headers   | dict  |  请求头字典  | / |
| hostname  | str |  域名  | www.example.com |
| port | int |  端口 | 443 |
| cookies | dict | COOKIE | / |
| params | dict |  在URL中包含的参数  | {'id': '1'} |
| post_hint | str  | post文件上传类型  | / |
| post_data | dict |  POST数据  | / |
| data | str | 原始请求头 | / |
| netloc | str | 包含协议的域名 | https://www.example.com:443 |

- self.response :
| 名称 | 类型 | 描述  | 示例 |
| --------- | -------- | -------- | ------- |
| status_code | int | 返回状态码 | 200 |
| content | byte | 返回字节类型 | /  |
| headers    | dict | 请求头  | / |
| raw    | str | 返回包的http返回文本 | / |
| text   | str  |   返回文本  | / |

- self.generateItemdatas() :
generateItemdatas()会将参数名、参数值及其所处的可控点整理后返回
```
>> iterdatas = self.generateItemdatas()
>> print(iterdatas)
[
    ["id", "1", "DATA"],
    ["username", "admin", "DATA"],
]
```

- self.insertPayload(key, value, position, payload) :
令参数名为key，参数值为value，并向参数值后添加payload
最终返回其对应可控点修改后的数据
常配合self.generateItemdatas()使用
```
>> datas = self.insertPayload("username", "admin", "DATA", "'--+")
>> print(datas)
{"username": "admin'--+", "passwd": "admin"}
>> r = request.get(url, data=datas)
```

- self.req(position, payload) :
payload为对应可控点修改后的数据，可以为self.insertPayload的返回
```
>> datas = {"username": "admin'--+", "passwd": "admin"}
>> r = self.req("DATA", datas)
>> print(r)
… # r为request的返回
```


## 示范

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/3/3

from urllib.parse import urlparse
import requests

from lib.helper.compare import compare
from api import generateResponse, conf, KB, VulType, PLACE, Type, PluginBase


class Z0SCAN(PluginBase):
    name = "other-nginx_iis-prase" # 插件名
    desc = 'IIS/Nginx Parse' # 描述
    
    def condition(self):
        for k, v in self.response.webserver.items():
            if (k == "IIS" and compver("7.0", v, "7.5")) or (k == "NGINX" and compver("0.0.1", v, "0.8.37")):
                return True
        return False
    
    def audit(self):
        if self.condition():
            headers = self.requests.headers
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + "robots.txt/.php"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            ContentType = r.headers.get("Content-Type", '')
            if 'html' in ContentType and "allow" in r.text:
                result = self.generate_result()
                # 生成报告
                result.main(Type.REQUEST, # 扫描类型
                            self.requests.hostname, # 漏洞HOSTNAME
                            self.requests.url, # 漏洞URL
                            VulType.CODE_INJECTION, # 漏洞类型
                            PLACE.URL, # 触发漏洞的位置（多处则选中URL）
                            msg=None, # 漏洞利用说明
                            param=None, # 漏洞参数
                            payload=None # 漏洞利用Payload
                            )
                # 验证步骤(可以添加多个过程，如二次验证)
                result.step("Request",
                           r.reqinfo, # 请求体
                           generateResponse(r), # 响应体(由generateResponse生成)
                           "Content-Type:{}".format(ContentType) # 步骤的关键信息或步骤描述
                           )
                self.success(result)
```
