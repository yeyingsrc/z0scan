![z0scan](https://socialify.git.ci/JiuZero/z0scan/image?description=1&font=Source+Code+Pro&name=1&owner=1&pattern=Solid&theme=Auto)

<h4 align="center" dir="auto">
  English | <a href="https://github.com/JiuZero/z0scan/blob/master/README.zh-CN.MD">中文</a> | <a href="https://jiuzero.github.io/tags/z0scan/">Document</a>
</p>

<p align="center">
  <a href="https://www.python.org/">
      <img src="https://img.shields.io/badge/Language-Python3-yellow.svg">
  <a href="https://github.com/JiuZero/z0scan">
      <img src="https://img.shields.io/pypi/v/z0scan">
  <a href="https://www.gnu.org/licenses/gpl-2.0.en.html">
      <img src="https://img.shields.io/badge/License-GPL2-_red.svg">
      <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/jiuzero/z0scan">
  </a>
</p>

## ⚠️ Disclaimer

> If you engage in any illegal activities while using this project and its included tools, you shall bear the corresponding consequences. We assume no legal or joint liability.

> By using this project or by any other express or implied acceptance of this agreement, you are deemed to have read and agreed to be bound by the terms herein.

## 🌟 Advantages

1. Integration of WAF detection, fingerprint information, and plugin scanning  
2. Capability to parse parameters in complex formats such as Json, XML, and pseudo-static parameters (Beta)  
3. SQLite3 support for storing scan records and other data  
4. Open-source based on Python3 with full cross-platform support  
5. Support for IPV6 domain name resolution (Beta)  

## 🔧 Installation

Install via **Pypi**  
```bash
pip install z0scan
z0
```

Install via **GitHub** clone  
```bash
git clone https://github.com/JiuZero/z0scan
cd z0scan
pip install -r requirements.txt
python3 z0.py
```

## 🚀 Usage Examples

### Passive Scanning

By default, `passive scanning` (browser forwards traffic to port 5920)  
```
z0 scan -s 127.0.0.1:5920
```

![example](doc/example0.png)

Commonly recommended  
```
z0 scan -s 127.0.0.1:5920 --risk 0,1,2,3 --level 2 --disable cmdi,unauth
```

### Active Scanning

By default, `active scanning`  
```
# Initiate active detection from Burp/Yakit request traffic (recommended)
z0 scan -s 127.0.0.1:5920
```

![example](doc/example1.png)

```
# Direct detection
z0 scan -u https://example.com/?id=1
# Traverse URL list for detection
z0 scan -f urls.txt
```

![example](doc/example2.png)

- For more detailed information, please refer to: [Documentation](https://jiuzero.github.io/tags/z0scan/)

## ✨ Plugin List

- PerFile

| Plugin Name | Description | Risk |
|:---:|:----:|:----:|
| sqli-bool | SQL Boolean-based Blind Injection Detection | 2 |
| sqli-time | SQL Time-based Blind Injection Detection | 2 |
| sqli-error | SQL Error-based Injection Detection | 2 |
| codei-asp | ASP Code Execution | 3 |
| codei-php | PHP Code Execution | 3 |
| cmdi | Command Execution | 3 |
| other-objectdese | Deserialization Parameter Analysis | 3 |
| sensi-js | JS Sensitive Information Leakage | 0 |
| sensi-jsonp | Jsonp Sensitive Information Leakage | 1 |
| sensi-php-realpath | PHP Real Path Discovery | 0 |
| redirect | Redirect | 1 |
| sensi-webpack | Webpack Source Code Leakage | 1 |
| other-webdav-passive | WebDAV Service Passive Discovery | 1 |
| xpathi-error | Error-based XPATH Injection Detection | 2 |
| trave-path | Path Traversal | 2 |
| sensi-backup_1 | Backup File Detection Based on Files | 1 |
| sensi-viewstate | Unencrypted VIEWSTATE Discovery | 0 |
| xss | XSS Scanning Based on JS Semantics | 1 |
| crlf_1 | CRLF Vulnerability Detection | 2 |
| cors-passive | CORS Vulnerability Detection (Passive Analysis) | 2 |
| unauth | Unauthorized Access Vulnerability | 2 |
| leakpwd-page-passive | Weak Password on Admin Login Page | 2 |
| sensi-editfile | Editor Backup File Leakage | 1 |
| sensi-sourcecode | Source Code Leakage | 1 |
| captcha-bypass | Captcha Bypass | 0 |

- PerFolder

| Plugin Name | Description | Risk |
|:---:|:----:|:----:|
| sensi-backup_2 | Backup File Scanning Based on Directories | 1 |
| trave-list | Directory Listing | 2 |
| sensi-repository | Repository Source Code Leakage | 1 |
| sensi-php-phpinfo | Phpinfo File Discovery | 0 |
| upload-oss | OSS Bucket Arbitrary File Upload | 2 |

- PerServer

| Plugin Name | Description | Risk |
|:---:|:----:|:----:|
| sensi-errorpage | Error Page Sensitive Information Leakage | 0 |
| xss-net | .NET Universal XSS | 1 |
| other-dns-zonetransfer | DNS Zone Transfer Vulnerability | 1 |
| xss-flash | Flash Universal XSS | 1 |
| other-idea-parse | Idea Directory Parsing | 1 |
| other-xst | XST Vulnerability Detection | -1 |
| other-webdav-active | WebDAV Service Discovery | 1 |
| upload-put | Arbitrary File Upload Based on PUT Request | 3 |
| sensi-backup_3 | Backup File Detection Based on Domain | 1 |
| cors-active | CORS Vulnerability Detection (Active Discovery) | 2 |
| crlf_3 | CRLF Line Injection Vulnerability | 2 |
| other-hosti | Host Header Injection Attack Detection | 1 |
| other-oss-takeover | OSS Bucket Takeover Vulnerability | 3 |
| sensi-iis-shortname | IIS Short Filename Vulnerability | 0 |

## 🎯 Limitations

- [ ] Lack of built-in crawler solution  
- [ ] Low efficiency of Python code (Codon?)  
- [ ] Duplicate detection issues (higher deduplication requirements)  

## 🔆 Changelog & License

- Changelog: [CHANGELOG](https://github.com/JiuZero/z0scan/blob/master/doc/CHANGELOG.MD)  

- GPL-2.0 License: [LICENSE](https://github.com/JiuZero/z0scan/blob/master/LICENSE)  

## 📝 Contact

| Platform | Contact |
|:---:|:----:|
| WeiXin | JiuZer1 |
| QQ | 1703417187 |
| Email | jiuzer0@qq.com |