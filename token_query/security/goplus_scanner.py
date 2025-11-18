"""
GoPlus Labs 代币安全检测模块
提供用户关心的代币安全信息（非代码漏洞）
"""
import requests
from typing import Optional, Dict, Any, Tuple
import sys

# GoPlus Labs API 端点
GOPLUS_API_BASE = "https://api.gopluslabs.io/api/v1"

# 链 ID 映射
CHAIN_ID_MAP = {
    "ethereum": "1",
    "bsc": "56",
    "polygon": "137",
    "arbitrum": "42161",
    "optimism": "10",
    "avalanche": "43114",
    "sui": "101",  # Sui 主网链 ID
    "solana": "100",  # Solana 主网链 ID
}


def _parse_bool(value: Any) -> Optional[bool]:
    """解析布尔值（支持字符串 "0"/"1" 格式）"""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value == "1" or value.lower() == "true"
    return bool(value)


def _parse_int(value: Any) -> Optional[int]:
    """解析整数（支持字符串格式）"""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(float(value))  # 先转 float 再转 int，处理 "100000000" 这样的字符串
        except (ValueError, TypeError):
            return None
    return None


def _parse_float(value: Any) -> Optional[float]:
    """解析浮点数（支持字符串格式）"""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
    return None


def get_token_security_info(token_address: str, chain: str = "ethereum", try_all_evm: bool = False) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    从 GoPlus Labs 获取代币安全信息
    
    参数:
        token_address: 代币合约地址
        chain: 链名称（ethereum, bsc, polygon 等）
        try_all_evm: 如果是 EVM 链且未找到数据，是否尝试所有 EVM 链
    
    返回:
        (代币安全信息字典, 错误消息)
        如果成功，返回 (info_dict, None)
        如果失败但有特定错误消息，返回 (None, error_message)
        如果失败且无特定错误消息，返回 (None, None)
    """
    chain_id = CHAIN_ID_MAP.get(chain.lower())
    if not chain_id:
        return None, None
    
    # EVM 链列表（按常用程度排序）
    EVM_CHAINS_ORDER = ["ethereum", "bsc", "polygon", "arbitrum", "optimism", "avalanche"]
    
    # 确定要尝试的链列表
    if try_all_evm and chain.lower() in EVM_CHAINS_ORDER:
        # 如果指定了链，先尝试指定的，然后尝试其他
        chains_to_try = [chain.lower()] + [c for c in EVM_CHAINS_ORDER if c != chain.lower()]
    else:
        chains_to_try = [chain.lower()]
    
    last_error_msg = None
    
    for try_chain in chains_to_try:
        try_chain_id = CHAIN_ID_MAP.get(try_chain)
        if not try_chain_id:
            continue
        
        try:
            # Solana 和 Sui 使用特殊的端点格式
            if try_chain == "solana":
                url = f"{GOPLUS_API_BASE}/solana/token_security"
            elif try_chain == "sui":
                url = f"{GOPLUS_API_BASE}/sui/token_security"
            else:
                url = f"{GOPLUS_API_BASE}/token_security/{try_chain_id}"
            
            params = {
                "contract_addresses": token_address
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # GoPlus API 返回格式: {"code": 1, "message": "OK", "result": {address: {...}}}
            # 如果 code 不为 1，检查是否有特定的错误消息
            if data.get("code") != 1:
                error_msg = data.get("message", "未知错误")
                # 检查是否是"新币检测中"的提示
                if "新币" in error_msg or "数据尚未被收录" in error_msg or "正在自动检测" in error_msg or "请稍后再试" in error_msg:
                    return None, error_msg
                # 对于 Sui，如果是链不支持的错误，继续尝试
                if try_chain == "sui" and ("not support" in error_msg.lower() or "unsupported" in error_msg.lower()):
                    continue
                # 其他错误保存，继续尝试其他链
                last_error_msg = error_msg
                continue
            
            if "result" in data:
                result = data["result"]
                # 如果 result 是 None 或空，继续尝试其他链
                if result is None or not result:
                    continue
                # 如果 result 是字典，查找代币信息
                if isinstance(result, dict):
                    if token_address.lower() in result:
                        return result[token_address.lower()], None
                    # 尝试不区分大小写
                    for addr, info in result.items():
                        if addr.lower() == token_address.lower():
                            return info, None
            
            # 如果到这里还没返回，继续尝试下一个链
            continue
            
        except requests.exceptions.RequestException as e:
            # 网络错误，继续尝试下一个链
            if try_chain != "sui":
                last_error_msg = f"网络请求失败: {e}"
            continue
        except Exception as e:
            # 其他错误，继续尝试下一个链
            if try_chain != "sui":
                last_error_msg = f"解析响应失败: {e}"
            continue
    
    # 所有链都尝试过了，返回最后的错误消息或 None
    return None, last_error_msg


def format_goplus_results(security_info: Dict[str, Any]) -> str:
    """
    格式化 GoPlus Labs 的安全检测结果（美化输出，添加中文）
    
    参数:
        security_info: GoPlus Labs 返回的安全信息字典
    
    返回:
        格式化的字符串
    """
    if not security_info:
        return ""
    
    output_lines = []
    output_lines.append("")
    output_lines.append("╔" + "═" * 78 + "╗")
    output_lines.append("║" + " " * 20 + "代币安全信息 (GoPlus Labs)" + " " * 30 + "║")
    output_lines.append("╠" + "═" * 78 + "╣")
    
    # 基本信息
    token_name = security_info.get("token_name", "N/A")
    if token_name and token_name != "N/A":
        output_lines.append("║" + f"  代币名称: {token_name}".ljust(79) + "║")
    
    # 安全风险检测（处理字符串 "0"/"1" 格式）
    is_open_source = _parse_bool(security_info.get("is_open_source"))
    is_proxy = _parse_bool(security_info.get("is_proxy"))
    is_mintable = _parse_bool(security_info.get("is_mintable"))
    is_blacklisted = _parse_bool(security_info.get("is_blacklisted"))
    is_honeypot = _parse_bool(security_info.get("is_honeypot"))
    is_anti_whale = _parse_bool(security_info.get("is_anti_whale"))
    is_whitelisted = _parse_bool(security_info.get("is_whitelisted"))
    
    # 交易税费（处理字符串格式）
    buy_tax = _parse_float(security_info.get("buy_tax"))
    sell_tax = _parse_float(security_info.get("sell_tax"))
    
    # 持有者信息
    holder_count = _parse_int(security_info.get("holder_count"))
    total_supply = _parse_int(security_info.get("total_supply"))
    
    # 安全风险列表
    risk_items = []
    
    # 开源状态
    if is_open_source is not None:
        status = "是" if is_open_source else "否"
        output_lines.append("║" + f"  合约开源: {status}".ljust(79) + "║")
        if not is_open_source:
            risk_items.append("合约未开源，无法查看源代码")
    
    if is_proxy is not None:
        status = "是" if is_proxy else "否"
        output_lines.append("║" + f"  代理合约: {status}".ljust(79) + "║")
        if is_proxy:
            risk_items.append("使用了代理合约，可能存在升级风险")
    
    if is_mintable is not None:
        status = "是" if is_mintable else "否"
        output_lines.append("║" + f"  可增发代币: {status}".ljust(79) + "║")
        if is_mintable:
            risk_items.append("代币可以增发，可能导致通胀")
    
    if is_blacklisted is not None:
        status = "是" if is_blacklisted else "否"
        output_lines.append("║" + f"  黑名单功能: {status}".ljust(79) + "║")
        if is_blacklisted:
            risk_items.append("合约包含黑名单功能，可能限制交易")
    
    if is_honeypot is not None:
        status = "是" if is_honeypot else "否"
        output_lines.append("║" + f"  蜜罐检测: {status}".ljust(79) + "║")
        if is_honeypot:
            risk_items.append("检测到蜜罐机制，可能无法卖出代币")
    
    if is_anti_whale is not None:
        status = "是" if is_anti_whale else "否"
        output_lines.append("║" + f"  反鲸鱼机制: {status}".ljust(79) + "║")
        if is_anti_whale:
            risk_items.append("存在反鲸鱼机制，可能限制大额交易")
    
    if is_whitelisted is not None:
        status = "是" if is_whitelisted else "否"
        output_lines.append("║" + f"  白名单功能: {status}".ljust(79) + "║")
        if is_whitelisted:
            risk_items.append("存在白名单功能，可能限制交易")
    
    # 交易税费
    if buy_tax is not None or sell_tax is not None:
        buy_tax_str = f"{buy_tax}%" if buy_tax is not None else "N/A"
        sell_tax_str = f"{sell_tax}%" if sell_tax is not None else "N/A"
        output_lines.append("║" + f"  买入税费: {buy_tax_str}".ljust(79) + "║")
        output_lines.append("║" + f"  卖出税费: {sell_tax_str}".ljust(79) + "║")
        
        if buy_tax and buy_tax > 10:
            risk_items.append(f"买入税费过高 ({buy_tax}%)")
        if sell_tax and sell_tax > 10:
            risk_items.append(f"卖出税费过高 ({sell_tax}%)")
        if buy_tax and sell_tax and (buy_tax > 5 or sell_tax > 5):
            risk_items.append("交易税费较高，可能影响交易体验")
    
    # 持有者信息
    if holder_count is not None:
        output_lines.append("║" + f"  持有者数量: {holder_count:,}".ljust(79) + "║")
        if holder_count < 100:
            risk_items.append("持有者数量较少，可能存在集中持有风险")
    
    if total_supply is not None:
        # 格式化总供应量（如果很大，使用科学计数法）
        if total_supply > 1e12:
            supply_str = f"{total_supply / 1e12:.2f}T"
        elif total_supply > 1e9:
            supply_str = f"{total_supply / 1e9:.2f}B"
        elif total_supply > 1e6:
            supply_str = f"{total_supply / 1e6:.2f}M"
        else:
            supply_str = f"{total_supply:,}"
        output_lines.append("║" + f"  总供应量: {supply_str}".ljust(79) + "║")
    
    output_lines.append("╚" + "═" * 78 + "╝")
    
    if risk_items:
        output_lines.append("")
        output_lines.append("风险提示:")
        output_lines.append("─" * 80)
        for risk in risk_items:
            output_lines.append(f"  {risk}")
    
    # 其他安全信息
    trading_cooldown = _parse_bool(security_info.get("trading_cooldown"))
    cannot_buy = _parse_bool(security_info.get("cannot_buy"))
    cannot_sell_all = _parse_bool(security_info.get("cannot_sell_all"))
    
    additional_risks = []
    if trading_cooldown:
        additional_risks.append("存在交易冷却时间限制")
    if cannot_buy:
        additional_risks.append("无法买入代币")
    if cannot_sell_all:
        additional_risks.append("无法全部卖出代币")
    
    if additional_risks:
        output_lines.append("")
        output_lines.append("严重风险:")
        output_lines.append("─" * 80)
        for risk in additional_risks:
            output_lines.append(f"  {risk}")
    
    # 持有者分布信息
    holders = security_info.get("holders", [])
    if holders and len(holders) > 0:
        output_lines.append("")
        output_lines.append("持有者分布:")
        output_lines.append("─" * 80)
        # 显示前5个持有者
        for i, holder in enumerate(holders[:5], 1):
            address = holder.get("address", "N/A")
            percent = holder.get("percent", 0)
            balance = holder.get("balance", 0)
            is_contract = holder.get("is_contract", 0)
            contract_tag = " (合约)" if is_contract else ""
            
            # 格式化百分比
            if isinstance(percent, str):
                try:
                    percent = float(percent)
                except:
                    percent = 0
            
            output_lines.append(f"  {i}. {address[:10]}...{address[-8:]}{contract_tag}")
            # 格式化余额
            try:
                # 尝试转换为数字并格式化
                balance_num = _parse_int(balance) or _parse_float(balance)
                if balance_num is not None:
                    balance_str = f"{int(balance_num):,}"
                else:
                    balance_str = str(balance)
            except (ValueError, TypeError):
                balance_str = str(balance)
            output_lines.append(f"     持有比例: {percent:.2f}% | 余额: {balance_str}")
        
        if len(holders) > 5:
            output_lines.append(f"  ... 还有 {len(holders) - 5} 个持有者")
    
    output_lines.append("")
    output_lines.append("提示: 以上信息由 GoPlus Labs 提供，仅供参考")
    output_lines.append("   更多信息: https://gopluslabs.io/token-security")
    
    return "\n".join(output_lines)

