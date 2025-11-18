"""
Solana链代币查询模块
"""
import requests
from typing import Optional, Dict, Any

from ..config import RPC_ENDPOINTS


def query_solana_token(token_address: str) -> Optional[Dict[str, Any]]:
    """查询Solana代币"""
    rpc_url = RPC_ENDPOINTS["solana"]
    
    # Solana使用JSON-RPC，格式不同
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenSupply",
        "params": [token_address]
    }
    
    try:
        response = requests.post(rpc_url, json=payload, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if result and "result" in result:
            supply_info = result["result"]
            value = supply_info.get("value", {})
            
            # 获取代币元数据（需要使用SPL Token Registry或其他API）
            # 这里简化处理，只返回供应量
            
            return {
                "name": "N/A (需要额外API)",
                "symbol": "N/A (需要额外API)",
                "decimals": value.get("decimals", 0),
                "totalSupply": value.get("amount", "0"),
                "chain": "solana",
                "address": token_address,
                "note": "Solana代币元数据需要额外的API查询"
            }
    except Exception as e:
        print(f"   Solana查询失败: {e}")
        return None
    
    return None

