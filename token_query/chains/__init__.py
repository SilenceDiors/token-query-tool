"""
链查询模块
"""
from .evm import query_erc20_token
from .sui import query_sui_token
from .solana import query_solana_token

__all__ = ['query_erc20_token', 'query_sui_token', 'query_solana_token']

