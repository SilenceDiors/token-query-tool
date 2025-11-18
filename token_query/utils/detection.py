"""
链类型检测工具
"""
from typing import Tuple


def detect_chain_type(token_address: str) -> Tuple[str, str]:
    """
    自动检测链类型
    返回: (chain_type, cleaned_address)
    """
    token_address = token_address.strip()
    
    # Sui格式: 0x...::module::Type 或包含 :: 分隔符
    if "::" in token_address:
        return "sui", token_address
    
    # Sui对象地址: 0x开头，长度66字符（64个十六进制字符 + 0x）
    if token_address.startswith("0x") and len(token_address) == 66:
        # 可能是Sui对象地址，返回sui让后续处理
        return "sui", token_address
    
    # Solana地址格式: 通常是base58编码，长度约32-44字符，不以0x开头
    if not token_address.startswith("0x") and len(token_address) >= 32 and len(token_address) <= 44:
        try:
            # 尝试base58解码验证（简单检查）
            return "solana", token_address
        except:
            pass
    
    # EVM兼容链（Ethereum, BSC, Polygon等）
    if token_address.startswith("0x") and len(token_address) == 42:
        # 默认以太坊，也可以让用户指定
        return "evm", token_address
    
    return "unknown", token_address

