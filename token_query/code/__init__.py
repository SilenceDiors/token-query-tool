"""
代码获取模块
"""
from .evm_code import get_evm_contract_code
from .sui_code import get_sui_move_code
from .solana_code import get_solana_program_code

__all__ = ['get_evm_contract_code', 'get_sui_move_code', 'get_solana_program_code']

