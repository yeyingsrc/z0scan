# Z0SCAN CHANGE LOGS

**2025.2.7**
1. 新增PerServer插件
* IISShortName IIS短文件名漏洞 (参考lijiejie/IIS\_shortname\_Scanner)
1. 修复IIS服务正则匹配问题
2. 对指纹进行合并调整 (也做了少量的删减)
3. 向config中引入更多的配置，允许更高的自定义

**2025.2.8**
1. 修复响应头部匹配问题
2. 添加WAF被动检测逻辑 (部分正则匹配来自Wafw00f)
3. 完善服务指纹匹配以获取服务版本信息 (允许漏洞检测插件读取)
4. 对level数值范围进行调整
5. 插件调整
* 调整IISShortName插件以支持高版本IIS短文件名漏洞发现 (参考abc123info/iis7.5-10.x-ShortNameFuzz)

**2025.2.9**
1. 新增PerServer插件:
* NginxWebcache Nginx错误配置-Webcache缓存清除 (参考stark0de/nginxpwner)
* NginxCRLF Nginx错误配置-CRLF注入 (参考stark0de/nginxpwner)
* NginxVariableLeakage Nginx错误配置-变量读取 (参考stark0de/nginxpwner)

**2025.2.10**
1. 修复了baseproxy下请求编码问题
2. 添加了启发式WAF逻辑 (逻辑来自Nmap)
3. 添加服务版本匹配逻辑，允许插件调用

**2025.2.11**
1. 增加了WAF记录
2. 修复了几处Bug
3. 新增PerServer插件
* OSSTakeover 可能的储存桶接管漏洞
4. 新增Fingprints指纹
* OSS 用于检测OSS服务
5. 对Level的划分做出调整（见插件列表）

**2025.2.12**
1. 添加了对伪静态SQL注入点的判断（目前仅支持盲注的伪静态发现）
2. 添加了对HQL语法报错的正则匹配
[] 发现SQLiTime存在结果不返回问题（未知Bug）

**2025.3.3**
1. 修复了高版本Python下的模块导入问题（自此兼容性为Python >= 3.7）
2. 全面对框架进行了修订，对相应的代码做出调整，全面提供伪静态注入的支持

**2025.3.7**
1. 改用数据库存储及读取Waf检测历史及URL检测历史

**2025.3.9**
1. 对框架的部分功能做出细微调整
2. 插件调整
* 修复OSSTakeover存在的致命Bug

**2025.3.11**
1. 新增PerFile插件
* XpathiError Xpath注入检测-基于报错
* Redirect 重定向检测

**2025.3.13**
1. 插件调整
* 优化了SQLiBool的逻辑，对Payloads做出调整以实现在WAF下的检测
2. 插件描述及相关信息英文化输出
3. 部分插件实现参数分发的多线程

**2025.3.14**
1. 对终端配色方案做出调整以兼容Win下的色彩输出

**2025.3.21**
1. 调整输出方式以解决输出乱序问题
2. 提供了pip安装

### 2025.3.21 发布

**2025.3.25**
1. 优化框架结构: 正则规则与目录字典外置于data中
2. 支持了在触发WAF后的正则匹配（优先级: 正则匹配>页面差异比较）

**2025.3.26**
1. 对数据库储存结构做出调整
2. 部分插件重命名

**2025.3.27**
1. 修正了相似跳过机制
2. logger的调用位置变动

**2025.4.6**
1. 修复了HTTPS代理问题（向上兼容Python13.2+）
2. 修复了多线程的变量共享问题
3. Level使用数列划分
4. 优化代码结构，减少代码量

**2025.4.12**
1. 修复线程池关闭问题
2. 插件调整
* 调整SQLiBool的Payload，降低WAF拦截率
* 加入了新的JsSensitive规则
1. 修复了大量的SyntaxWarning
2. 对相似URL作出调整

**2025.4.13**
1. 修复了一处逻辑问题&一些小Bug

### 2025.4.13 发布