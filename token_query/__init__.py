"""
Token Query Tool - 通用多链代币查询工具
"""
__version__ = "1.0.0"

from .cli import query_token_universal, get_contract_code_only, main

__all__ = ['query_token_universal', 'get_contract_code_only', 'main']

