#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/4/11

import setuptools
import os, io
from lib.core.settings import VERSION, SITE
import shutil
import tempfile


current_dir = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(current_dir, "README.md"), encoding="utf-8") as fd:
    desc = fd.read()
with io.open(os.path.join(current_dir, "requirements.txt"), encoding="utf-8") as fd:
    install_requires = fd.readlines()
    install_requires = [i.strip() for i in install_requires]

env_dir = tempfile.mkdtemp(prefix="z0scan-install-")
shutil.copytree(os.path.abspath(os.getcwd()), os.path.join(env_dir, "z0scan"))
os.chdir(env_dir)

setuptools.setup(
    name='z0scan',
    version=VERSION,
    author='JiuZero',
    author_email='jiuzer0@qq.com',
    description='An efficient active/passive scanning tool for vulnerability detection in risk assets | 一款风险资产漏洞检测与辅助性的高效主、被动扫描工具.',
    long_description=desc,
    packages=setuptools.find_packages(),
    entry_points={"console_scripts": ["z0scan=z0scan.z0scan:main"]},
    include_package_data=True,
    package_data={"z0scan": ["*", "data/*", "certs/*", "output/*", "data/dict/*", "doc/*"]},
    long_description_content_type='text/markdown',
    keywords='z0scan, security, scanner, web, python3',
    platforms=['any'],
    url=SITE,
    python_requires='>=3.0',
    install_requires=install_requires,
    classifiers=(
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    )
)

dist_dir = os.path.join(env_dir, "dist")
shutil.move(dist_dir, os.path.join(current_dir, "dist"))