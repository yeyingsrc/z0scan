#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from api import VulType, Type, PLACE, PluginBase, generateResponse, random_str, random_num, conf
import requests

class Z0SCAN(PluginBase):
    name = "upload-oss-arbitrary"
    desc = "Detect the vulnerability of uploading arbitrary files to OSS"
    
    def _generate_testfile(self):
        filename = f"{random_str(8)}_{random_num(6)}.txt"
        content = f"{random_str(12)}"
        return filename, content
    
    def _test_upload(self, base_url, method="PUT"):
        filename, expect_content = self._generate_testfile()
        target_url = f"{base_url}/{filename}"
        try:
            if method == "PUT":
                r1 = requests.put(
                    target_url,
                    data=expect_content,
                    headers=self.requests.headers,
                    verify=False,
                    timeout=conf.timeout
                )
            else:
                files = {'file': (filename, expect_content)}
                r1 = requests.post(
                    base_url,
                    files=files,
                    headers=self.requests.headers,
                    verify=False,
                    timeout=conf.timeout
                )
            
            # 验证上传结果
            if r1.status_code in [200, 201, 204]:
                r2 = requests.get(
                    target_url,
                    headers={"Range": "bytes=0-50"},  # 部分请求避免大文件
                    timeout=conf.timeout
                )
                if r2.status_code == 200 and expect_content in r2.text:
                    r = r1, r2
                    return r
                if r2.status_code == 206 and expect_content in r2.text:
                    return r
        except Exception as e:
            pass
        return None
    
    def condition(self):
        for k, v in self.response.webserver.items():
            if k == "OSS":
                return True
        return False
    
    def audit(self):
        if not self.condition():
            return
        test_endpoints = [
            self.requests.netloc,
            f"{self.requests.netloc}/uploads",
            f"{self.requests.netloc}/static"
        ]
        if conf.level >= 3:
            test_endpoints.extend([
                f"{self.requests.netloc}/public",
                f"{self.requests.netloc}/upload"
            ])
        test_methods = ["PUT"] if conf.level < 2 else ["PUT", "POST"]
        for endpoint in test_endpoints:
            for method in test_methods:
                if r := self._test_upload(endpoint, method):
                    r1, r2 = r
                    result = self.generate_result()
                    result.main(Type.REQUEST, self.requests.hostname, r1.url, VulType.FILEUPLOAD, PLACE.URL, msg="OSS arbitrary file upload vulnerability (no signature authentication required)")
                    result.step("File upload request", self.requests.raw, generateResponse(r1), f"Target URL: {r1.url}")
                    result.step("File verification request", f"GET {r2.url}", generateResponse(r2), "Content matches verification string")
                    self.success(result)
                    return