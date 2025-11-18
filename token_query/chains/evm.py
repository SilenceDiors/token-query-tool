"""
EVM链代币查询模块
支持 Ethereum, BSC, Polygon, Arbitrum, Optimism, Avalanche
"""
import requests
from typing import Optional, Dict, Any

from ..config import RPC_ENDPOINTS, EVM_CHAINS, ERC20_ABI


def call_evm_rpc(url: str, method: str, params: list) -> Optional[Dict[str, Any]]:
    """调用EVM兼容链的RPC"""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return None


def encode_function_call(function_signature: str) -> str:
    """编码函数调用（前4字节）"""
    try:
        from web3 import Web3
        w3 = Web3()
        return w3.keccak(text=function_signature)[:4].hex()
    except:
        return ""


def query_erc20_token(token_address: str, chain: str = "ethereum") -> Optional[Dict[str, Any]]:
    """查询ERC20代币（支持EVM链）"""
    if chain not in EVM_CHAINS:
        chain = "ethereum"  # 默认以太坊
    
    rpc_url = RPC_ENDPOINTS.get(chain, RPC_ENDPOINTS["ethereum"])
    
    # 获取函数选择器（简化版，实际应该用web3）
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        contract = w3.eth.contract(address=Web3.to_checksum_address(token_address), abi=ERC20_ABI)
        
        try:
            name = contract.functions.name().call()
            symbol = contract.functions.symbol().call()
            decimals = contract.functions.decimals().call()
            total_supply = contract.functions.totalSupply().call()
            
            return {
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "totalSupply": str(total_supply),
                "chain": chain,
                "address": token_address
            }
        except Exception as e:
            print(f"   查询合约失败: {e}")
            return None
    except ImportError:
        print("   需要安装 web3 库: pip install web3")
        return None

