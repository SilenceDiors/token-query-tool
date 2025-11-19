"""
Sui Move 合约安全扫描模块
基于模式匹配，无需编译，直接分析源代码
检测 Sui Move 常见的安全漏洞模式
"""
from typing import Dict, Any, List, Optional
import re


def scan_sui_move_code(source_code: Dict[str, str], package_address: str) -> Dict[str, Any]:
    """
    扫描 Sui Move 代码，查找常见的安全问题
    
    参数:
        source_code: 模块名 -> Move 源代码的字典
        package_address: Package 地址
    
    返回:
        包含扫描结果的字典
    """
    all_issues = []
    
    for module_name, move_code in source_code.items():
        lines = move_code.split('\n')
        
        # 1. 检查 init 函数
        all_issues.extend(_check_init_function(lines, module_name))
        
        # 2. 检查权限控制
        all_issues.extend(_check_access_control(lines, module_name))
        
        # 3. 检查可增发代币
        all_issues.extend(_check_mintable(lines, module_name))
        
        # 4. 检查暂停功能
        all_issues.extend(_check_pause_function(lines, module_name))
        
        # 5. 检查转账函数权限
        all_issues.extend(_check_transfer_functions(lines, module_name))
        
        # 6. 检查硬编码的敏感信息
        all_issues.extend(_check_hardcoded_secrets(lines, module_name))
        
        # 7. 检查未检查的返回值
        all_issues.extend(_check_unchecked_return_values(lines, module_name))
        
        # 8. 检查未限制的循环
        all_issues.extend(_check_unbounded_loops(lines, module_name))
        
        # 9. 检查不安全的类型转换
        all_issues.extend(_check_unsafe_type_casting(lines, module_name))
        
        # 10. 检查共享对象权限
        all_issues.extend(_check_shared_object_permissions(lines, module_name))
        
        # 11. 检查升级权限
        all_issues.extend(_check_upgrade_permissions(lines, module_name))
        
        # 12. 检查事件缺失
        all_issues.extend(_check_missing_events(lines, module_name))
        
        # 13. 检查资源管理
        all_issues.extend(_check_resource_management(lines, module_name))
        
        # 14. 检查整数运算
        all_issues.extend(_check_arithmetic_operations(lines, module_name))
        
        # 15. 检查函数可见性
        all_issues.extend(_check_function_visibility(lines, module_name))
    
    # 按严重程度分类
    critical = [i for i in all_issues if i.get('severity') == 'CRITICAL']
    high = [i for i in all_issues if i.get('severity') == 'HIGH']
    medium = [i for i in all_issues if i.get('severity') == 'MEDIUM']
    low = [i for i in all_issues if i.get('severity') == 'LOW']
    info = [i for i in all_issues if i.get('severity') == 'INFO']
    
    return {
        "package_address": package_address,
        "issues": critical + high + medium + low,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "summary": {
            "total_issues": len(all_issues),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "info": len(info)
        }
    }


def _check_init_function(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查 init 函数"""
    issues = []
    in_init = False
    init_line = 0
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测 init 函数
        if re.search(r'fun\s+init\s*\(', stripped):
            in_init = True
            init_line = i
            
            # 检查是否有固定供应量
            if 'FixedSupply' in line or 'fixed_supply' in line.lower():
                issues.append({
                    "severity": "INFO",
                    "title": "固定供应量设置",
                    "description": "代币供应量在初始化时固定，无法增发",
                    "line": i,
                    "module": module_name,
                    "function": "init",
                    "recommendation": "确认这是预期的设计"
                })
            
            # 检查是否有可增发设置
            if 'mint' in line.lower() or 'MintCap' in line:
                issues.append({
                    "severity": "MEDIUM",
                    "title": "init 函数中可能包含增发逻辑",
                    "description": "代币可能在初始化时设置了增发能力，需要验证增发权限控制",
                    "line": i,
                    "module": module_name,
                    "function": "init",
                    "recommendation": "验证增发权限是否受到适当控制"
                })
        
        if in_init:
            # 检查 init 函数中的关键操作
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                in_init = False
                continue
            
            # 检查是否有硬编码的关键值
            if re.search(r'0x[a-fA-F0-9]{64}', stripped):
                issues.append({
                    "severity": "HIGH",
                    "title": "init 函数中可能包含硬编码地址",
                    "description": "硬编码的地址可能表示固定的管理员或关键地址",
                    "line": i,
                    "module": module_name,
                    "function": "init",
                    "recommendation": "确认硬编码地址是预期的，考虑使用配置参数"
                })
    
    return issues


def _check_access_control(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查权限控制问题"""
    issues = []
    current_function = None
    function_line = 0
    has_access_control = False
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测函数定义
        func_match = re.search(r'fun\s+(\w+)\s*\(', stripped)
        if func_match:
            current_function = func_match.group(1)
            function_line = i
            has_access_control = False
            
            # 检查关键函数名
            critical_keywords = ['transfer', 'mint', 'burn', 'pause', 'unpause', 
                                 'set', 'update', 'change', 'admin', 'withdraw']
            
            if any(keyword in current_function.lower() for keyword in critical_keywords):
                # 检查是否有访问控制（检查函数参数和修饰符）
                # Move 中通常通过参数传递权限对象
                if '&' in stripped and ('AdminCap' in stripped or 'TreasuryCap' in stripped or 
                                        'OwnerCap' in stripped or 'Cap' in stripped):
                    has_access_control = True
                else:
                    # 检查函数体中的权限检查
                    # 先标记，后续检查函数体
                    pass
        
        # 在函数体中检查权限验证
        if current_function and not has_access_control:
            # 检查是否有权限验证
            if any(keyword in stripped for keyword in ['assert', 'abort', 'require']):
                # 检查是否验证了权限
                if any(keyword in stripped for keyword in ['AdminCap', 'TreasuryCap', 'OwnerCap', 
                                                          'has_cap', 'check_cap']):
                    has_access_control = True
            
            # 函数结束
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                if not has_access_control and current_function:
                    critical_keywords = ['transfer', 'mint', 'burn', 'pause', 'unpause', 
                                       'set', 'update', 'change', 'admin', 'withdraw']
                    if any(keyword in current_function.lower() for keyword in critical_keywords):
                        issues.append({
                            "severity": "HIGH",
                            "title": f"关键函数 {current_function} 可能缺少访问控制",
                            "description": f"函数 {current_function} 可能应该验证调用者权限",
                            "line": function_line,
                            "module": module_name,
                            "function": current_function,
                            "recommendation": "添加权限验证，使用 AdminCap、TreasuryCap 等权限对象"
                        })
                current_function = None
                has_access_control = False
    
    return issues


def _check_transfer_functions(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查转账相关函数"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 查找转账函数
        if re.search(r'fun\s+transfer', stripped, re.IGNORECASE):
            # 检查是否有权限控制
            if 'AdminCap' not in stripped and 'TreasuryCap' not in stripped:
                # 检查函数体中是否有权限验证
                has_control = False
                for j in range(i, min(len(lines), i+30)):
                    if '}' in lines[j]:
                        break
                    if any(keyword in lines[j] for keyword in ['AdminCap', 'TreasuryCap', 'assert', 'abort']):
                        has_control = True
                        break
                
                if not has_control:
                    issues.append({
                        "severity": "MEDIUM",
                        "title": "转账函数可能缺少权限控制",
                        "description": "转账函数应该验证调用者权限",
                        "line": i,
                        "module": module_name,
                        "function": "transfer",
                        "recommendation": "添加权限验证或确认这是预期的公开函数"
                    })
    
    return issues


def _check_mintable(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查是否可增发，并分析mint形式、最大值限制等"""
    issues = []
    mint_info = {
        "has_mint": False,
        "mint_in_init": False,
        "mint_function_exists": False,
        "has_max_supply": False,
        "max_supply_value": None,
        "mint_function_line": None,
        "init_mint_line": None,
        "mint_access_control": False
    }
    
    in_init = False
    in_mint_function = False
    init_line = 0
    mint_function_line = 0
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测init函数
        if re.search(r'fun\s+init\s*\(', stripped):
            in_init = True
            init_line = i
        
        # 检测mint函数
        if re.search(r'fun\s+mint', stripped, re.IGNORECASE):
            mint_info["has_mint"] = True
            mint_info["mint_function_exists"] = True
            mint_function_line = i
            mint_info["mint_function_line"] = i
            in_mint_function = True
            
            # 检查权限控制
            has_control = 'TreasuryCap' in stripped or 'MintCap' in stripped or 'AdminCap' in stripped
            if has_control:
                mint_info["mint_access_control"] = True
        
        # 在init函数中查找mint相关操作
        if in_init:
            if 'mint' in stripped.lower() or 'MintCap' in stripped or 'TreasuryCap' in stripped:
                mint_info["has_mint"] = True
                mint_info["mint_in_init"] = True
                mint_info["init_mint_line"] = i
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                in_init = False
        
        # 在mint函数中查找权限控制
        if in_mint_function:
            if any(keyword in stripped for keyword in ['TreasuryCap', 'MintCap', 'AdminCap', 'assert', 'abort']):
                mint_info["mint_access_control"] = True
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                in_mint_function = False
                # 检查函数体中是否有权限验证
                for j in range(mint_function_line, min(len(lines), mint_function_line+30)):
                    if '}' in lines[j]:
                        break
                    if any(keyword in lines[j] for keyword in ['TreasuryCap', 'MintCap', 'AdminCap']):
                        mint_info["mint_access_control"] = True
                        break
        
        # 查找最大供应量限制
        if re.search(r'(maxSupply|max_supply|MAX_SUPPLY|cap|CAP|total_supply)', stripped, re.IGNORECASE):
            mint_info["has_max_supply"] = True
            # 尝试提取数值
            num_match = re.search(r'(\d+)', stripped)
            if num_match:
                mint_info["max_supply_value"] = num_match.group(1)
        
        # 查找FixedSupply相关
        if 'FixedSupply' in stripped or 'fixed_supply' in stripped.lower():
            mint_info["has_max_supply"] = True
    
    if not mint_info["has_mint"]:
        return issues
    
    # 构建分析结果
    mint_type = "未知"
    if mint_info["mint_in_init"] and not mint_info["mint_function_exists"]:
        mint_type = "仅部署时一次性铸造"
    elif mint_info["mint_in_init"] and mint_info["mint_function_exists"]:
        mint_type = "部署时铸造 + 运行态可铸造"
    elif mint_info["mint_function_exists"]:
        mint_type = "运行态可铸造"
    
    max_supply_info = "无限制"
    if mint_info["has_max_supply"]:
        if mint_info["max_supply_value"]:
            max_supply_info = f"有最大值限制: {mint_info['max_supply_value']}"
        else:
            max_supply_info = "有最大值限制（具体值需查看代码）"
    
    access_control_info = "有权限控制" if mint_info["mint_access_control"] else "缺少权限控制"
    
    description = f"铸造形式: {mint_type}\n"
    description += f"最大值限制: {max_supply_info}\n"
    description += f"权限控制: {access_control_info}"
    
    if mint_info["mint_function_line"]:
        line_num = mint_info["mint_function_line"]
    elif mint_info["init_mint_line"]:
        line_num = mint_info["init_mint_line"]
    else:
        line_num = 0
    
    severity = "HIGH" if not mint_info["mint_access_control"] else "INFO"
    
    issues.append({
        "severity": severity,
        "title": "Mint功能分析",
        "description": description,
        "line": line_num,
        "module": module_name,
        "function": "mint",
        "mint_analysis": {
            "mint_type": mint_type,
            "max_supply": max_supply_info,
            "access_control": access_control_info,
            "has_max_supply": mint_info["has_max_supply"],
            "mint_in_init": mint_info["mint_in_init"],
            "mint_function_exists": mint_info["mint_function_exists"]
        },
        "recommendation": "确认mint权限控制和最大供应量限制是否符合预期"
    })
    
    return issues


def _check_pause_function(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查暂停功能"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 查找暂停函数
        if re.search(r'fun\s+(pause|unpause|set_paused)', stripped, re.IGNORECASE):
            # 检查是否有权限控制
            has_control = 'AdminCap' in stripped or 'OwnerCap' in stripped
            
            if not has_control:
                # 检查函数体中是否有权限验证
                for j in range(i, min(len(lines), i+30)):
                    if '}' in lines[j]:
                        break
                    if any(keyword in lines[j] for keyword in ['AdminCap', 'OwnerCap', 'assert', 'abort']):
                        has_control = True
                        break
            
            issues.append({
                "severity": "HIGH" if not has_control else "MEDIUM",
                "title": "检测到暂停功能",
                "description": "合约包含暂停交易的功能" + ("，但缺少权限控制" if not has_control else "，需要验证权限控制"),
                "line": i,
                "module": module_name,
                "function": re.search(r'fun\s+(\w+)', stripped).group(1) if re.search(r'fun\s+(\w+)', stripped) else "pause/unpause",
                "recommendation": "确保暂停功能有适当的权限控制，使用 AdminCap 或 OwnerCap"
            })
    
    return issues


def _check_hardcoded_secrets(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查硬编码的敏感信息"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查私钥模式（64个十六进制字符）
        if re.search(r'0x[a-fA-F0-9]{64}', stripped):
            issues.append({
                "severity": "CRITICAL",
                "title": "硬编码的私钥或敏感信息",
                "description": "代码中可能包含硬编码的私钥或敏感信息",
                "line": i,
                "module": module_name,
                "function": "N/A",
                "recommendation": "立即移除硬编码的私钥，使用环境变量或安全的密钥管理"
            })
        
        # 检查硬编码的地址
        if re.search(r'0x[a-fA-F0-9]{40,}', stripped) and 'address' in stripped.lower():
            # 排除函数参数中的地址
            if 'fun' not in stripped and 'parameter' not in stripped.lower():
                issues.append({
                    "severity": "MEDIUM",
                    "title": "硬编码的地址",
                    "description": "代码中可能包含硬编码的地址，可能表示固定的管理员或关键地址",
                    "line": i,
                    "module": module_name,
                    "function": "N/A",
                    "recommendation": "确认硬编码地址是预期的，考虑使用配置参数"
                })
    
    return issues


def _check_unchecked_return_values(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查未检查的返回值"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查可能返回错误的函数调用
        # Move 中通常使用 Result<T, E> 或 Option<T>
        if re.search(r'\.(unwrap|expect|get)', stripped):
            # 检查是否有错误处理
            if 'match' not in stripped and 'if' not in stripped:
                issues.append({
                    "severity": "MEDIUM",
                    "title": "可能未检查的返回值",
                    "description": "使用 unwrap 或 expect 可能导致程序中止，应该使用 match 或 if 进行错误处理",
                    "line": i,
                    "module": module_name,
                    "function": "N/A",
                    "recommendation": "使用 match 或 if 进行错误处理，避免使用 unwrap"
                })
    
    return issues


def _check_unbounded_loops(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查未限制的循环"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测循环
        if 'while' in stripped or 'loop' in stripped:
            # 检查是否有明确的边界或退出条件
            if 'length' not in stripped and 'size' not in stripped and 'break' not in stripped:
                issues.append({
                    "severity": "MEDIUM",
                    "title": "未限制的循环",
                    "description": "循环可能无限执行或遍历大量元素，导致 gas 耗尽",
                    "line": i,
                    "module": module_name,
                    "function": "N/A",
                    "recommendation": "限制循环的最大迭代次数或添加明确的退出条件"
                })
    
    return issues


def _check_unsafe_type_casting(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查不安全的类型转换"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查类型转换（Move 中使用 as 关键字）
        if ' as ' in stripped:
            # 检查是否有范围检查
            if 'assert' not in stripped and 'abort' not in stripped:
                # 检查前几行是否有检查
                has_check = False
                for j in range(max(0, i-5), i):
                    if 'assert' in lines[j] or 'abort' in lines[j] or 'if' in lines[j]:
                        has_check = True
                        break
                
                if not has_check:
                    issues.append({
                        "severity": "MEDIUM",
                        "title": "不安全的类型转换",
                        "description": "类型转换可能导致溢出或数据丢失",
                        "line": i,
                        "module": module_name,
                        "function": "N/A",
                        "recommendation": "在类型转换前添加范围检查"
                    })
    
    return issues


def _check_shared_object_permissions(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查共享对象权限"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查共享对象定义
        if 'shared' in stripped and 'struct' in stripped:
            # 检查是否有适当的权限控制
            if 'key' not in stripped and 'store' not in stripped:
                issues.append({
                    "severity": "MEDIUM",
                    "title": "共享对象可能缺少权限控制",
                    "description": "共享对象应该使用 key 或 store 能力进行适当的权限控制",
                    "line": i,
                    "module": module_name,
                    "function": "N/A",
                    "recommendation": "确保共享对象有适当的权限控制"
                })
    
    return issues


def _check_upgrade_permissions(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查升级权限"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查升级相关函数
        if re.search(r'fun\s+(upgrade|migrate)', stripped, re.IGNORECASE):
            # 检查是否有权限控制
            has_control = 'AdminCap' in stripped or 'UpgradeCap' in stripped
            
            if not has_control:
                issues.append({
                    "severity": "HIGH",
                    "title": "升级函数可能缺少权限控制",
                    "description": "升级函数应该验证调用者权限，防止未授权的升级",
                    "line": i,
                    "module": module_name,
                    "function": re.search(r'fun\s+(\w+)', stripped).group(1) if re.search(r'fun\s+(\w+)', stripped) else "upgrade",
                    "recommendation": "添加权限验证，使用 UpgradeCap 或 AdminCap"
                })
    
    return issues


def _check_missing_events(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查事件缺失"""
    issues = []
    
    # 查找关键操作
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查关键操作
        if any(keyword in stripped for keyword in ['transfer', 'mint', 'burn', 'pause', 'unpause']):
            # 检查是否有事件定义
            has_event = False
            for j in range(max(0, i-50), min(len(lines), i+50)):
                if 'event' in lines[j].lower() and any(keyword in lines[j].lower() for keyword in ['transfer', 'mint', 'burn', 'pause']):
                    has_event = True
                    break
            
            if not has_event:
                issues.append({
                    "severity": "LOW",
                    "title": "重要操作可能缺少事件记录",
                    "description": f"第 {i} 行的操作可能应该发出事件",
                    "line": i,
                    "module": module_name,
                    "function": "N/A",
                    "recommendation": "为重要的状态变更操作添加事件记录"
                })
    
    return issues


def _check_resource_management(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查资源管理"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查资源泄漏（未正确销毁或转移）
        if 'move' in stripped and 'destroy' not in stripped and 'transfer' not in stripped:
            # 检查是否是资源类型
            if 'Coin' in stripped or 'Object' in stripped:
                issues.append({
                    "severity": "MEDIUM",
                    "title": "可能的资源泄漏",
                    "description": "资源可能未被正确销毁或转移",
                    "line": i,
                    "module": module_name,
                    "function": "N/A",
                    "recommendation": "确保资源被正确销毁或转移，避免资源泄漏"
                })
    
    return issues


def _check_arithmetic_operations(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查整数运算"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查算术运算
        if re.search(r'[\+\-\*/]', stripped):
            # Move 有内置的溢出保护，但检查是否有显式的错误处理
            if 'assert' not in stripped and 'abort' not in stripped:
                issues.append({
                    "severity": "LOW",
                    "title": "算术运算可能缺少错误处理",
                    "description": "虽然 Move 有内置保护，但显式的错误处理可以提高代码健壮性",
                    "line": i,
                    "module": module_name,
                    "function": "N/A",
                    "recommendation": "考虑添加显式的错误处理"
                })
    
    return issues


def _check_function_visibility(lines: List[str], module_name: str) -> List[Dict[str, Any]]:
    """检查函数可见性"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查公共函数
        if re.search(r'public\s+fun', stripped):
            func_match = re.search(r'fun\s+(\w+)', stripped)
            if func_match:
                func_name = func_match.group(1).lower()
                # 检查是否是只读函数（应该用 entry）
                if any(keyword in func_name for keyword in ['get', 'read', 'view', 'query', 'is', 'has']):
                    if 'entry' not in stripped:
                        issues.append({
                            "severity": "LOW",
                            "title": f"函数 {func_match.group(1)} 可能应该使用 entry 而不是 public",
                            "description": "只读函数使用 entry 可以节省 gas",
                            "line": i,
                            "module": module_name,
                            "function": func_match.group(1),
                            "recommendation": "如果函数只被外部调用，使用 entry 代替 public"
                        })
    
    return issues


def format_sui_scan_results(results: Dict[str, Any]) -> str:
    """
    格式化 Sui 扫描结果
    """
    if not results.get("issues"):
        return """
╔══════════════════════════════════════════════════════════════════════════════╗
║              Sui Move 安全扫描结果                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  未检测到常见的安全问题模式                                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    summary = results.get("summary", {})
    critical = results.get("critical", [])
    high = results.get("high", [])
    medium = results.get("medium", [])
    low = results.get("low", [])
    info = results.get("info", [])
    
    output_lines = []
    output_lines.append("")
    output_lines.append("╔══════════════════════════════════════════════════════════════════════════════╗")
    output_lines.append("║              Sui Move 安全扫描结果                                      ║")
    output_lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
    output_lines.append(f"║  Package 地址: {results.get('package_address', 'N/A')}")
    output_lines.append(f"║  总问题数: {summary.get('total_issues', 0)}")
    output_lines.append(f"║  严重 (CRITICAL): {summary.get('critical', 0)}")
    output_lines.append(f"║  高危 (HIGH): {summary.get('high', 0)}")
    output_lines.append(f"║  中危 (MEDIUM): {summary.get('medium', 0)}")
    output_lines.append(f"║  低危 (LOW): {summary.get('low', 0)}")
    output_lines.append(f"║  信息 (INFO): {summary.get('info', 0)}")
    output_lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
    output_lines.append("")
    
    # 提取mint分析信息（如果有）
    mint_analysis = None
    other_issues = []
    for issue in results.get("issues", []):
        if issue.get('title') == 'Mint功能分析':
            mint_analysis = issue
        else:
            other_issues.append(issue)
    
    # 如果有mint分析，优先显示
    if mint_analysis:
        output_lines.append("╔══════════════════════════════════════════════════════════════════════════════╗")
        output_lines.append("║                      Mint功能分析                                        ║")
        output_lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
        mint_data = mint_analysis.get('mint_analysis', {})
        output_lines.append(f"║  铸造形式: {mint_data.get('mint_type', '未知')}")
        output_lines.append(f"║  最大值限制: {mint_data.get('max_supply', '未知')}")
        output_lines.append(f"║  权限控制: {mint_data.get('access_control', '未知')}")
        output_lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        output_lines.append("")
    
    output_lines.append("详细问题列表:")
    output_lines.append("─" * 80)
    output_lines.append("")
    
    # 按严重程度排序显示（排除mint分析，因为已经单独显示）
    all_issues = [i for i in (critical + high + medium + low + info) if i.get('title') != 'Mint功能分析']
    
    for idx, issue in enumerate(all_issues, 1):
        severity = issue.get('severity', 'UNKNOWN')
        output_lines.append(f"【问题 #{idx}】{severity} - {issue.get('title', '未知问题')}")
        output_lines.append("─" * 80)
        output_lines.append(f"  描述: {issue.get('description', '无描述')}")
        output_lines.append(f"  位置: [{issue.get('module', 'N/A')}] 第 {issue.get('line', '?')} 行")
        if issue.get('function') and issue.get('function') != 'N/A':
            output_lines.append(f"  函数: {issue.get('function')}")
        if issue.get('recommendation'):
            output_lines.append(f"  建议: {issue.get('recommendation')}")
        output_lines.append("")
    
    return "\n".join(output_lines)

