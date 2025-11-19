#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用多链代币查询工具 - 主入口
"""
import sys
import os
import warnings

# 抑制 urllib3 的 OpenSSL 警告
warnings.filterwarnings('ignore', category=UserWarning, module='urllib3')
warnings.filterwarnings('ignore', message='.*urllib3 v2 only supports OpenSSL.*')
warnings.filterwarnings('ignore', message='.*NotOpenSSLWarning.*')

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 尝试加载python-dotenv（如果可用）
try:
    from dotenv import load_dotenv
    load_dotenv()  # 自动加载.env文件
except ImportError:
    # 如果没有安装python-dotenv，手动加载.env文件
    def load_env_file():
        env_file = os.path.join(os.path.dirname(__file__), '.env')
        if os.path.exists(env_file):
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        os.environ[key] = value
    load_env_file()

from token_query.cli import main

if __name__ == "__main__":
    main()

