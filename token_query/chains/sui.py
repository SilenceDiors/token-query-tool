"""
Sui链代币查询模块
"""
import json
import requests
from typing import Optional, Dict, Any

from ..config import RPC_ENDPOINTS


def query_sui_token(token_address: str) -> Optional[Dict[str, Any]]:
    """查询Sui代币"""
    rpc_url = RPC_ENDPOINTS["sui"]
    
    # 如果输入的是对象地址（没有::），需要先查询对象获取类型
    coin_type = token_address
    if "::" not in token_address:
        # 先查询对象信息获取类型
        print(f"   查询对象信息: {token_address}")
        try:
            object_payload = {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "sui_getObject",
                "params": [token_address, {"showType": True, "showContent": True}]
            }
            object_response = requests.post(rpc_url, json=object_payload, timeout=10)
            object_response.raise_for_status()
            object_result = object_response.json()
            
            # 检查是否有错误
            if "error" in object_result:
                error_msg = object_result["error"].get("message", "未知错误")
                print(f"   查询对象失败: {error_msg}")
                return None
            
            if object_result and "result" in object_result and object_result["result"]:
                obj_data = object_result["result"].get("data", {})
                
                # 尝试从对象数据中获取类型
                # 1. 直接从 data.type 获取
                if "type" in obj_data:
                    obj_type = obj_data["type"]
                    print(f"   获取到对象类型: {obj_type}")
                # 2. 从 content.type 获取（Coin对象等）
                elif "content" in obj_data:
                    content = obj_data["content"]
                    if isinstance(content, dict) and "type" in content:
                        obj_type = content["type"]
                        print(f"   获取到对象类型: {obj_type}")
                    else:
                        obj_type = None
                else:
                    obj_type = None
                
                # 如果获取到类型，尝试提取代币类型
                if obj_type:
                    # 检查是否是 package 类型
                    if obj_type == "package":
                        print(f"   该地址是一个 Package（智能合约包），不是代币对象")
                        print(f"   Package 地址: {token_address}")
                        
                        # 尝试查询 package 的模块信息
                        try:
                            print(f"   尝试查询 Package 模块信息...")
                            module_payload = {
                                "jsonrpc": "2.0",
                                "id": 0,
                                "method": "sui_getNormalizedMoveModulesByPackage",
                                "params": [token_address]
                            }
                            module_response = requests.post(rpc_url, json=module_payload, timeout=10)
                            module_response.raise_for_status()
                            module_result = module_response.json()
                            
                            if module_result and "result" in module_result and module_result["result"]:
                                modules = module_result["result"]
                                print(f"   找到 {len(modules)} 个模块:")
                                
                                possible_coin_types = []
                                for module_name, module_info in modules.items():
                                    print(f"      - {module_name}")
                                    
                                    # 查找模块中定义的结构体类型
                                    if "structs" in module_info:
                                        structs = module_info["structs"]
                                        for struct_name, struct_info in structs.items():
                                            struct_type = f"{token_address}::{module_name}::{struct_name}"
                                            # 检查是否是代币相关类型
                                            if "Coin" in struct_name or "Token" in struct_name:
                                                possible_coin_types.append(struct_type)
                                            # 也列出所有结构体供参考
                                            if len(possible_coin_types) < 5:  # 限制显示数量
                                                possible_coin_types.append(struct_type)
                                
                                if possible_coin_types:
                                    print(f"   发现可能的代币类型:")
                                    for coin_type in possible_coin_types[:5]:  # 最多显示5个
                                        print(f"      - {coin_type}")
                                    if len(possible_coin_types) > 5:
                                        print(f"      ... 还有 {len(possible_coin_types) - 5} 个类型")
                                
                                print(f"   提示: 要查询代币，请使用完整类型格式:")
                                print(f"      {token_address}::<模块名>::<类型名>")
                                print(f"   例如: {token_address}::lineup::<Type>")
                        except Exception as e:
                            print(f"   查询模块信息失败: {e}")
                        
                        return None
                    
                    # 如果是Coin对象，提取泛型参数中的类型
                    # 格式: 0x2::coin::Coin<0x...::module::Type>
                    elif "Coin<" in obj_type:
                        import re
                        match = re.search(r'Coin<([^>]+)>', obj_type)
                        if match:
                            coin_type = match.group(1)
                            print(f"   从Coin对象提取代币类型: {coin_type}")
                        else:
                            coin_type = obj_type
                    elif "::" in obj_type:
                        # 如果类型包含::，可能是代币类型
                        coin_type = obj_type
                        print(f"   使用对象类型作为代币类型: {coin_type}")
                    else:
                        coin_type = obj_type
                        print(f"   对象类型可能不是代币: {obj_type}")
                        print(f"   将尝试查询代币元数据...")
                else:
                    print(f"   无法从对象中获取类型")
                    print(f"   对象数据结构: {json.dumps(obj_data, indent=2, ensure_ascii=False)[:300]}...")
                    print(f"   尝试直接使用地址作为类型查询...")
            else:
                print(f"   对象不存在或无法访问")
                return None
        except requests.exceptions.RequestException as e:
            print(f"   网络请求失败: {e}")
            return None
        except Exception as e:
            print(f"   查询对象信息失败: {e}")
            return None
    
    # 使用类型查询代币元数据
    print(f"   查询代币元数据: {coin_type}")
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "suix_getCoinMetadata",
        "params": [coin_type]
    }
    
    try:
        response = requests.post(rpc_url, json=payload, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        # 检查是否有错误
        if "error" in result:
            error_msg = result["error"].get("message", "未知错误")
            error_code = result["error"].get("code", "")
            print(f"   查询代币元数据失败: {error_msg} (错误代码: {error_code})")
            if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
                print(f"   提示: 该地址可能不是代币类型，或代币不存在")
            return None
        
        if result and "result" in result:
            if result["result"] is None:
                print(f"   代币元数据为空，该类型可能不是代币")
                print(f"   提示: 请确认输入的是代币类型格式 (0x...::module::Type)")
                return None
            
            metadata = result["result"]
            
            # 获取总供应量
            supply_payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "suix_getTotalSupply",
                "params": [coin_type]
            }
            supply_response = requests.post(rpc_url, json=supply_payload, timeout=10)
            supply_result = supply_response.json() if supply_response.status_code == 200 else None
            
            total_supply = None
            if supply_result:
                if "result" in supply_result:
                    # 成功获取
                    result = supply_result["result"]
                    if isinstance(result, dict):
                        total_supply = result.get("value")
                    elif isinstance(result, str):
                        # 有些 RPC 可能直接返回字符串
                        try:
                            total_supply = int(result)
                        except (ValueError, TypeError):
                            pass
                    elif isinstance(result, (int, str)):
                        # 直接是数字或字符串
                        try:
                            total_supply = int(result) if isinstance(result, str) else result
                        except (ValueError, TypeError):
                            pass
                elif "error" in supply_result:
                    # RPC 返回错误，可能是 regulated currency 或其他机制
                    # 尝试使用其他方法获取供应量（如果需要的话）
                    error_msg = supply_result["error"].get("message", "")
                    # 对于 regulated currency，TreasuryCap 可能不存在，这是正常的
                    # 我们仍然返回其他信息，只是 totalSupply 为 None
                    pass
            
            return {
                "name": metadata.get("name", "N/A"),
                "symbol": metadata.get("symbol", "N/A"),
                "decimals": metadata.get("decimals", 0),
                "totalSupply": total_supply,
                "description": metadata.get("description", ""),
                "iconUrl": metadata.get("iconUrl", ""),
                "chain": "sui",
                "address": token_address,
                "coinType": coin_type  # 保存实际使用的类型
            }
        else:
            print(f"   RPC响应格式异常")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"   网络请求失败: {e}")
        print(f"   请检查网络连接或RPC节点是否可用")
        return None
    except Exception as e:
        print(f"   Sui查询失败: {e}")
        import traceback
        print(f"   详细错误: {traceback.format_exc()}")
        return None
    
    return None

