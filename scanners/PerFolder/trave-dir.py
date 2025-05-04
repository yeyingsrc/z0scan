#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# w8ay 2019/6/29
# JiuZero 2025/3/4

from api import VulType, PLACE, PluginBase, Type


class Z0SCAN(PluginBase):
    name = "trave-dir"
    desc = "Directory Traversal"

    def audit(self):

        resp_str = self.response.text
        flag_list = [
            "directory listing for",
            "<title>directory",
            "<head><title>index of",
            '<table summary="directory listing"',
            'last modified</a>',

        ]
        for i in flag_list:
            if i in resp_str.lower():
                result = self.generate_result()
                result.main(Type.ANALYZE, self.requests.hostname, self.requests.url, VulType.SENSITIVE, PLACE.URL)
                result.step("Request", self.requests.raw, self.response.raw, "Match Keyword {}".format(i))
                self.success(result)
                break
