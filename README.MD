![z0scan](https://socialify.git.ci/JiuZero/z0scan/image?description=1&font=Source+Code+Pro&name=1&owner=1&pattern=Solid&theme=Auto)

<h4 align="center" dir="auto">
  English | <a href="https://github.com/JiuZero/z0scan/blob/master/README.zh-CN.MD">中文</a> | <a href="https://github.com/JiuZero/z0scan-report">ReportSource</a>
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

> If you engage in any illegal activities while using this project or its included tools, you shall bear the consequences. We assume no legal or joint liability.

> By using this project or implicitly/explicitly accepting this agreement, you acknowledge that you have read and agreed to its terms.

## 🌟 Advantages

1. **Integration of WAF detection, fingerprinting, and plugin scanning**  
   *"Fewer WAF triggers, lower request volume, and precise targeting"*

2. **Support for pseudo-static pages and other vulnerabilities**  
   *"Broader detection coverage"*

3. **Assists in discovering sensitive information and potential vulnerabilities**  
   *"Enhanced discovery capabilities"*

4. **SQLite3-based storage for scan records and data**  
   *"Scalable and efficient"*

5. **Open-source Python3 implementation**  
   *"Highly customizable"*

## 🔧 Installation

Install via **Pypi**:
```bash
pip install z0scan
z0scan
```

Install via **GitHub**:
```bash
git clone https://github.com/JiuZero/z0scan
cd z0scan
pip install -r requirements.txt
python3 z0scan.py
```

## 🚀 Usage

```
usage: z0scan [options]

options:
  -h, --help            show this help message and exit
  -v, --version         Show program's version number and exit
  --debug               Show programs's exception
  -l LEVEL, --level LEVEL
                        Different level use different kind of scanner (Default 2)

Proxy:
  Passive Agent Mode Options

  -s SERVER_ADDR, --server-addr SERVER_ADDR
                        Server addr format:(ip:port)

Target:
  Options has to be provided to define the target(s)

  -u URL, --url URL     Target URL (e.g. "http://www.site.com/vuln.php?id=1")
  -f URL_FILE, --file URL_FILE
                        Scan multiple targets given in a textual file

Request:
  Network request options

  -p PROXY, --proxy PROXY
                        Use a proxy to connect to the target URL, Support
                        http,https,socks5,socks4 eg:http@127.0.0.1:8080 or
                        socks5@127.0.0.1:1080
  --timeout TIMEOUT     Seconds to wait before timeout connection (Default 6)
  --retry RETRY         Time out retrials times (Default 2)
  --random-agent        Use randomly selected HTTP User-Agent header value

Output:
  Output options

  --html                Output results to HTML (default: ./output/)
  --json JSON           Output results to JSON (default: ./output/)

Optimization:
  Optimization options

  -t THREADS, --threads THREADS
                        Max concurrent network requests (Default 31)
  -iw, --ignore-waf     Ignore WAF during detection
  -sf, --skip-fingerprint
                        Skip fingerprint scanning
  -sc, --scan-cookie    Scan cookies during detection
  --disable DISABLE     Disable specific scanners
  --able ABLE           Enable only specified scanners
```

## 🎉 Plugin List

- **PerFile**

| Plugin Name          | Description                          |
|----------------------|--------------------------------------|
| sqli-bool            | SQL Boolean-based Blind Injection    |
| sqli-time            | SQL Time-based Blind Injection       |
| sqli-error           | SQL Error-based Injection            |
| codei-asp            | ASP Code Execution                   |
| codei-php            | PHP Code Execution                   |
| cmdi                 | Command Execution                    |
| other-objectdese     | Deserialization Parameter Analysis   |
| sensi-js             | JS Sensitive Information Leakage     |
| sensi-jsonp          | JSONP Sensitive Information Leakage  |
| sensi-php-realpath   | PHP Real Path Disclosure             |
| redirect             | Open Redirect                        |
| webpack              | Webpack Source Code Leakage          |
| other-webdavFile     | WebDAV Detection (PerFile)           |
| xpathi-error         | Error-based XPath Injection          |
| trave-path           | Path Traversal                       |
| sensi-backupFile     | Backup File Detection (File-based)   |
| sensi-viewstate      | Unencrypted VIEWSTATE Disclosure     |

- **PerFolder**

| Plugin Name          | Description                          |
|----------------------|--------------------------------------|
| sensi-backupFolder   | Backup File Scanning                 |
| trave-list           | Directory Listing                    |
| upload-oss-Folder    | OSS File Upload (PerFolder)          |
| sensi-repository     | Source Code Repository Leakage       |
| sensi-php-phpinfo    | PHPInfo File Detection               |

- **PerServer**

| Plugin Name          | Description                          |
|----------------------|--------------------------------------|
| sensi-iis-shortname  | IIS Short Filename Vulnerability     |
| other-nginx_iis-parse| IIS/Nginx Parsing Vulnerability      |
| sensi-errorpage      | Error Page Sensitive Data Leakage    |
| other-oss-takeover   | OSS Bucket Takeover                  |
| xss-net              | .NET Universal XSS                   |
| other-dns-zonetransfer| DNS Zone Transfer Vulnerability      |
| crlf-nginx           | Nginx CRLF Injection                 |
| other-nginx-clearcache| Nginx Misconfiguration - Cache Clear |
| xss-flash            | Flash Universal XSS                  |
| sensi-nginx-readvar  | Nginx Misconfiguration - Variable Read |
| other-idea-parse     | Idea Directory Parsing               |
| other-xst            | XST Vulnerability                    |
| other-webdavPS       | WebDAV Detection (PerServer)         |
| upload-put           | PUT Request Arbitrary File Upload    |
| upload-oss-PS        | OSS File Upload (PerServer)          |
| sensi-backupPS       | Backup File Detection (Domain-based) |

- Plugin Development Guide:  
[DEV.MD](https://github.com/JiuZero/z0scan/blob/master/doc/DEV.MD)

## ✨ References

z0scan was inspired by the following projects (including but not limited to):
```
- [w13scan](https://github.com/w-digital-scanner/w13scan)
- [myscan](https://github.com/amcai/myscan)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [Vxscan](https://github.com/al0ne/Vxscan)
- [Sitadel](https://github.com/shenril/Sitadel)
etc…
```

- Full list: [THANKS.MD](https://github.com/JiuZero/z0scan/blob/master/doc/THANKS.MD)

## 🔆 Changelog & License

- Changelog: [CHANGELOG](https://github.com/JiuZero/z0scan/blob/master/doc/CHANGELOG.MD)  
- License: GPL-2.0 [LICENSE](https://github.com/JiuZero/z0scan/blob/master/LICENSE)

## ❤️ Contact

| Platform | Contact        |
|----------|----------------|
| QQ       | 1703417187     |
| Email    | jiuzer0@qq.com |
| WeChat   | JiuZer1        |