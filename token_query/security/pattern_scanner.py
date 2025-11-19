"""
基于模式匹配的安全扫描器
不需要编译，直接分析源代码文本
检测常见的安全漏洞模式
"""
import re
from typing import List, Dict, Any, Optional


def scan_with_patterns(source_code: str) -> List[Dict[str, Any]]:
    """
    使用模式匹配扫描 Solidity 代码
    
    参数:
        source_code: Solidity 源代码
    
    返回:
        检测到的问题列表
    """
    issues = []
    
    if not source_code or not isinstance(source_code, str):
        return issues
    
    lines = source_code.split('\n')
    
    # 1. 检查重入攻击模式
    issues.extend(_check_reentrancy(lines))
    
    # 2. 检查未初始化的存储变量
    issues.extend(_check_uninitialized_storage(lines))
    
    # 3. 检查整数溢出（Solidity 0.8+ 已内置保护，但检查旧版本）
    issues.extend(_check_arithmetic_overflow(lines))
    
    # 4. 检查未检查的外部调用返回值
    issues.extend(_check_unchecked_call_return(lines))
    
    # 5. 检查 tx.origin 使用（不安全）
    issues.extend(_check_tx_origin(lines))
    
    # 6. 检查 block.timestamp 依赖（可能被操纵）
    issues.extend(_check_block_timestamp(lines))
    
    # 7. 检查 delegatecall 使用（高风险）
    issues.extend(_check_delegatecall(lines))
    
    # 8. 检查 selfdestruct 使用（高风险）
    issues.extend(_check_selfdestruct(lines))
    
    # 9. 检查未受保护的函数（缺少访问控制）
    issues.extend(_check_unprotected_functions(lines))
    
    # 10. 检查硬编码的私钥或敏感信息
    issues.extend(_check_hardcoded_secrets(lines))
    
    # 11. 检查未限制的循环（可能导致 gas 耗尽）
    issues.extend(_check_unbounded_loops(lines))
    
    # 12. 检查不安全的随机数生成
    issues.extend(_check_weak_randomness(lines))
    
    # 13. 检查未使用的变量和函数
    issues.extend(_check_unused_variables(lines))
    
    # 14. 检查函数可见性（public vs external）
    issues.extend(_check_function_visibility(lines))
    
    # 15. 检查事件缺失（重要操作未记录事件）
    issues.extend(_check_missing_events(lines))
    
    # 16. 检查不安全的类型转换
    issues.extend(_check_unsafe_type_casting(lines))
    
    # 17. 检查 gas 优化问题
    issues.extend(_check_gas_optimization(lines))
    
    # 18. 检查权限控制问题
    issues.extend(_check_access_control(lines))
    
    # 19. 检查外部调用前的状态检查
    issues.extend(_check_state_before_external_call(lines))
    
    # 20. 检查函数返回值未使用
    issues.extend(_check_unused_return_value(lines))
    
    # 21. 分析mint功能
    mint_analysis = _analyze_mint_functionality(lines)
    if mint_analysis:
        issues.append(mint_analysis)
    
    return issues


def _check_reentrancy(lines: List[str]) -> List[Dict[str, Any]]:
    """检查重入攻击模式"""
    issues = []
    in_function = False
    function_name = None
    has_external_call = False
    has_state_change = False
    external_call_line = None
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测函数开始
        if 'function ' in stripped and '{' in stripped:
            in_function = True
            has_external_call = False
            has_state_change = False
            match = re.search(r'function\s+(\w+)', stripped)
            function_name = match.group(1) if match else "unknown"
            continue
        
        if in_function:
            # 检测外部调用（.call, .send, .transfer, .call.value）
            if re.search(r'\.(call|send|transfer|call\.value)', stripped):
                has_external_call = True
                external_call_line = i
            
            # 检测状态变量修改
            if re.search(r'(\w+)\s*=\s*[^=]', stripped) and not stripped.startswith('//'):
                # 排除局部变量（简单检查）
                if not re.search(r'(memory|storage|calldata)\s+\w+\s*=', stripped):
                    has_state_change = True
            
            # 函数结束
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                if has_external_call and has_state_change:
                    issues.append({
                        'severity': 'HIGH',
                        'title': '潜在的重入攻击风险',
                        'description': f'函数 {function_name} 在状态变量修改后进行了外部调用，可能存在重入攻击风险',
                        'line': external_call_line or i,
                        'recommendation': '使用 ReentrancyGuard 或检查-效果-交互（CEI）模式'
                    })
                in_function = False
    
    return issues


def _check_uninitialized_storage(lines: List[str]) -> List[Dict[str, Any]]:
    """检查未初始化的存储变量"""
    issues = []
    declared_vars = {}
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测存储变量声明
        match = re.search(r'(uint|int|bool|address|bytes|string|mapping)\s+(\w+)', stripped)
        if match and 'function' not in stripped and 'memory' not in stripped:
            var_type, var_name = match.groups()
            if var_name not in ['memory', 'storage', 'calldata']:
                declared_vars[var_name] = i
        
        # 检测变量使用（简单检查）
        for var_name, decl_line in declared_vars.items():
            if var_name in stripped and '=' not in stripped[:stripped.find(var_name)]:
                # 可能未初始化就使用
                if re.search(rf'\b{var_name}\b', stripped) and i > decl_line:
                    issues.append({
                        'severity': 'MEDIUM',
                        'title': f'可能未初始化的变量: {var_name}',
                        'description': f'变量 {var_name} 在第 {decl_line} 行声明，但可能在使用前未初始化',
                        'line': i,
                        'recommendation': '确保所有存储变量在使用前都已正确初始化'
                    })
                    break
    
    return issues


def _check_arithmetic_overflow(lines: List[str]) -> List[Dict[str, Any]]:
    """检查整数溢出（Solidity 0.8+ 已内置保护）"""
    issues = []
    pragma_version = None
    
    # 检查 Solidity 版本
    for line in lines:
        if 'pragma solidity' in line:
            match = re.search(r'(\d+)\.(\d+)', line)
            if match:
                major, minor = map(int, match.groups())
                if major < 0 or (major == 0 and minor < 8):
                    pragma_version = f"{major}.{minor}"
                    break
    
    if pragma_version:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # 检测算术运算
            if re.search(r'(\w+)\s*[+\-*/]\s*(\w+)', stripped) and 'SafeMath' not in stripped:
                issues.append({
                    'severity': 'HIGH',
                    'title': '潜在的整数溢出/下溢',
                    'description': f'Solidity {pragma_version} 版本中，算术运算可能导致溢出/下溢',
                    'line': i,
                    'recommendation': '使用 SafeMath 库或升级到 Solidity 0.8+'
                })
    
    return issues


def _check_unchecked_call_return(lines: List[str]) -> List[Dict[str, Any]]:
    """检查未检查的外部调用返回值"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测 .call() 或 .delegatecall() 但未检查返回值
        if re.search(r'\.(call|delegatecall)\(', stripped):
            if 'require(' not in stripped and 'if' not in stripped and 'assert' not in stripped:
                # 检查下一行是否检查返回值
                if i < len(lines):
                    next_line = lines[i].strip()
                    if 'require' not in next_line and 'if' not in next_line:
                        issues.append({
                            'severity': 'MEDIUM',
                            'title': '未检查的外部调用返回值',
                            'description': '.call() 或 .delegatecall() 的返回值未被检查',
                            'line': i,
                            'recommendation': '始终检查 .call() 和 .delegatecall() 的返回值'
                        })
    
    return issues


def _check_tx_origin(lines: List[str]) -> List[Dict[str, Any]]:
    """检查 tx.origin 使用"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        if 'tx.origin' in line:
            issues.append({
                'severity': 'MEDIUM',
                'title': '使用 tx.origin 进行身份验证',
                'description': 'tx.origin 可能被中间合约操纵，应使用 msg.sender',
                'line': i,
                'recommendation': '使用 msg.sender 代替 tx.origin 进行身份验证'
            })
    
    return issues


def _check_block_timestamp(lines: List[str]) -> List[Dict[str, Any]]:
    """检查 block.timestamp 依赖"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        if 'block.timestamp' in line or 'now' in line:
            # 检查是否用于关键逻辑
            if any(keyword in line for keyword in ['require', 'if', 'assert', '=']):
                issues.append({
                    'severity': 'LOW',
                    'title': '依赖 block.timestamp',
                    'description': 'block.timestamp 可能被矿工操纵（最多 ±15秒）',
                    'line': i,
                    'recommendation': '避免将 block.timestamp 用于关键业务逻辑'
                })
    
    return issues


def _check_delegatecall(lines: List[str]) -> List[Dict[str, Any]]:
    """检查 delegatecall 使用"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        if '.delegatecall(' in line:
            issues.append({
                'severity': 'HIGH',
                'title': '使用 delegatecall',
                'description': 'delegatecall 允许目标合约修改调用者的存储，存在高风险',
                'line': i,
                'recommendation': '谨慎使用 delegatecall，确保目标合约可信'
            })
    
    return issues


def _check_selfdestruct(lines: List[str]) -> List[Dict[str, Any]]:
    """检查 selfdestruct 使用"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        if 'selfdestruct' in line or 'suicide' in line:
            issues.append({
                'severity': 'HIGH',
                'title': '使用 selfdestruct',
                'description': 'selfdestruct 会销毁合约并转移所有余额',
                'line': i,
                'recommendation': '确保 selfdestruct 有适当的访问控制'
            })
    
    return issues


def _check_unprotected_functions(lines: List[str]) -> List[Dict[str, Any]]:
    """检查未受保护的函数"""
    issues = []
    current_function = None
    has_modifier = False
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测函数定义
        if 'function ' in stripped:
            match = re.search(r'function\s+(\w+)', stripped)
            if match:
                current_function = match.group(1)
                has_modifier = False
                
                # 检查是否有修饰符
                if 'public' in stripped or 'external' in stripped:
                    # 检查是否有 onlyOwner 等修饰符
                    if 'onlyOwner' in stripped or 'onlyRole' in stripped or 'modifier' in stripped:
                        has_modifier = True
                    else:
                        # 检查函数名是否暗示需要保护
                        if any(keyword in current_function.lower() for keyword in ['transfer', 'withdraw', 'mint', 'burn', 'pause', 'unpause', 'set']):
                            issues.append({
                                'severity': 'MEDIUM',
                                'title': f'未受保护的关键函数: {current_function}',
                                'description': f'函数 {current_function} 可能缺少访问控制修饰符',
                                'line': i,
                                'recommendation': '添加 onlyOwner 或其他访问控制修饰符'
                            })
    
    return issues


def _check_hardcoded_secrets(lines: List[str]) -> List[Dict[str, Any]]:
    """检查硬编码的私钥或敏感信息"""
    issues = []
    
    # 私钥模式（64个十六进制字符）
    private_key_pattern = r'0x[a-fA-F0-9]{64}'
    # 常见的硬编码值
    suspicious_patterns = [
        (r'private\s+key', '私钥'),
        (r'password\s*=\s*["\']', '密码'),
        (r'secret\s*=\s*["\']', '密钥'),
    ]
    
    for i, line in enumerate(lines, 1):
        # 检查私钥模式
        if re.search(private_key_pattern, line):
            issues.append({
                'severity': 'CRITICAL',
                'title': '硬编码的私钥或敏感信息',
                'description': '代码中可能包含硬编码的私钥或敏感信息',
                'line': i,
                'recommendation': '立即移除硬编码的私钥，使用环境变量或安全的密钥管理'
            })
        
        # 检查其他可疑模式
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    'severity': 'HIGH',
                    'title': f'硬编码的{desc}',
                    'description': f'代码中可能包含硬编码的{desc}',
                    'line': i,
                    'recommendation': '使用环境变量或安全的配置管理'
                })
    
    return issues


def _check_unbounded_loops(lines: List[str]) -> List[Dict[str, Any]]:
    """检查未限制的循环"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测循环
        if 'for (' in stripped or 'while (' in stripped:
            # 检查是否有明确的边界
            if 'length' in stripped or 'count' in stripped:
                # 检查是否有限制
                if 'require(' not in stripped and 'if' not in stripped:
                    issues.append({
                        'severity': 'MEDIUM',
                        'title': '未限制的循环',
                        'description': '循环可能遍历大量元素，导致 gas 耗尽',
                        'line': i,
                        'recommendation': '限制循环的最大迭代次数'
                    })
    
    return issues


def _check_weak_randomness(lines: List[str]) -> List[Dict[str, Any]]:
    """检查不安全的随机数生成"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测使用 block 属性作为随机数
        if any(attr in stripped for attr in ['block.timestamp', 'block.number', 'block.difficulty', 'blockhash']):
            if 'random' in stripped.lower() or 'rand' in stripped.lower():
                issues.append({
                    'severity': 'MEDIUM',
                    'title': '不安全的随机数生成',
                    'description': '使用 block 属性生成随机数可能被矿工操纵',
                    'line': i,
                    'recommendation': '使用 Chainlink VRF 或其他安全的随机数生成方案'
                })
    
    return issues


def _check_unused_variables(lines: List[str]) -> List[Dict[str, Any]]:
    """检查未使用的变量"""
    issues = []
    # 这是一个简化的检查，完整实现需要解析整个合约
    # 这里只检查明显的未使用变量（如声明但从未引用）
    return issues


def _check_function_visibility(lines: List[str]) -> List[Dict[str, Any]]:
    """检查函数可见性（public vs external）"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if 'function ' in stripped and 'public' in stripped:
            # 检查是否是只读函数（应该用 external）
            # 简单检查：如果函数名包含 get、view、read 等，可能是只读函数
            func_match = re.search(r'function\s+(\w+)', stripped)
            if func_match:
                func_name = func_match.group(1).lower()
                if any(keyword in func_name for keyword in ['get', 'read', 'view', 'query', 'is', 'has']):
                    # 检查函数体是否修改状态
                    # 这里简化处理，只检查函数签名
                    if 'view' not in stripped and 'pure' not in stripped:
                        issues.append({
                            'severity': 'LOW',
                            'title': f'函数 {func_match.group(1)} 可能应该使用 external 而不是 public',
                            'description': '只读函数使用 external 可以节省 gas',
                            'line': i,
                            'recommendation': '如果函数只被外部调用，使用 external 代替 public'
                        })
    
    return issues


def _check_missing_events(lines: List[str]) -> List[Dict[str, Any]]:
    """检查事件缺失（重要操作未记录事件）"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查关键操作是否有事件
        if any(keyword in stripped for keyword in ['transfer', 'mint', 'burn', 'approve']):
            # 检查是否是函数调用
            if 'function ' in stripped or '(' in stripped:
                # 检查前后是否有 event 定义
                # 简化检查：查找 event 关键字
                has_event = False
                for j in range(max(0, i-50), min(len(lines), i+50)):
                    if 'event ' in lines[j].lower() and any(keyword in lines[j].lower() for keyword in ['transfer', 'mint', 'burn', 'approve']):
                        has_event = True
                        break
                
                if not has_event:
                    issues.append({
                        'severity': 'MEDIUM',
                        'title': '重要操作可能缺少事件记录',
                        'description': f'第 {i} 行的操作可能应该发出事件',
                        'line': i,
                        'recommendation': '为重要的状态变更操作添加事件记录'
                    })
    
    return issues


def _check_unsafe_type_casting(lines: List[str]) -> List[Dict[str, Any]]:
    """检查不安全的类型转换"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查类型转换
        if re.search(r'\(uint\d+|int\d+|address|bytes\d*\)', stripped):
            # 检查是否有溢出保护
            if 'require' not in stripped and 'if' not in stripped:
                issues.append({
                    'severity': 'MEDIUM',
                    'title': '不安全的类型转换',
                    'description': '类型转换可能导致溢出或数据丢失',
                    'line': i,
                    'recommendation': '在类型转换前添加范围检查'
                })
    
    return issues


def _check_gas_optimization(lines: List[str]) -> List[Dict[str, Any]]:
    """检查 gas 优化问题"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查 storage 变量在循环中使用
        if 'for (' in stripped or 'while (' in stripped:
            # 检查循环体中是否有 storage 读取
            # 简化：检查后续几行
            for j in range(i, min(len(lines), i+20)):
                if '}' in lines[j]:
                    break
                if any(keyword in lines[j] for keyword in ['storage', '.length', 'mapping']):
                    issues.append({
                        'severity': 'LOW',
                        'title': '循环中可能重复读取 storage',
                        'description': '在循环中读取 storage 变量会消耗大量 gas',
                        'line': i,
                        'recommendation': '将 storage 变量缓存到 memory 中'
                    })
                    break
        
        # 检查使用 uint256 而不是 uint8（gas 优化）
        if re.search(r'uint8\s+\w+', stripped):
            issues.append({
                'severity': 'LOW',
                'title': '使用 uint8 可能浪费 gas',
                'description': 'uint8 在 storage 中仍占用 32 字节，使用 uint256 可能更节省 gas',
                'line': i,
                'recommendation': '考虑使用 uint256 代替 uint8（除非在 struct 中打包）'
            })
    
    return issues


def _check_access_control(lines: List[str]) -> List[Dict[str, Any]]:
    """检查权限控制问题"""
    issues = []
    owner_functions = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测关键函数
        if 'function ' in stripped:
            func_match = re.search(r'function\s+(\w+)', stripped)
            if func_match:
                func_name = func_match.group(1).lower()
                # 检查是否是关键函数
                if any(keyword in func_name for keyword in ['transfer', 'withdraw', 'mint', 'burn', 'pause', 'unpause', 'set', 'update', 'change']):
                    # 检查是否有访问控制
                    if 'onlyOwner' not in stripped and 'onlyRole' not in stripped and 'modifier' not in stripped:
                        owner_functions.append((i, func_match.group(1)))
    
    for line_num, func_name in owner_functions:
        issues.append({
            'severity': 'HIGH',
            'title': f'关键函数 {func_name} 缺少访问控制',
            'description': f'函数 {func_name} 可能应该添加 onlyOwner 或其他访问控制修饰符',
            'line': line_num,
            'recommendation': '添加访问控制修饰符（如 onlyOwner）'
        })
    
    return issues


def _check_state_before_external_call(lines: List[str]) -> List[Dict[str, Any]]:
    """检查外部调用前的状态检查（CEI 模式）"""
    issues = []
    in_function = False
    external_calls = []
    state_changes = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        if 'function ' in stripped:
            in_function = True
            external_calls = []
            state_changes = []
            continue
        
        if in_function:
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                # 函数结束，检查 CEI 模式
                for call_line, _ in external_calls:
                    for state_line, _ in state_changes:
                        if state_line > call_line:
                            issues.append({
                                'severity': 'HIGH',
                                'title': '违反检查-效果-交互（CEI）模式',
                                'description': '在外部调用后修改状态，可能导致重入攻击',
                                'line': call_line,
                                'recommendation': '先修改状态，再进行外部调用（CEI 模式）'
                            })
                in_function = False
                continue
            
            # 检测外部调用
            if re.search(r'\.(call|send|transfer|delegatecall)', stripped):
                external_calls.append((i, stripped))
            
            # 检测状态修改
            if re.search(r'(\w+)\s*=\s*[^=]', stripped) and 'memory' not in stripped and 'calldata' not in stripped:
                state_changes.append((i, stripped))
    
    return issues


def _check_unused_return_value(lines: List[str]) -> List[Dict[str, Any]]:
    """检查函数返回值未使用"""
    issues = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检查外部调用返回值未使用
        if re.search(r'\.(call|delegatecall|staticcall)\(', stripped):
            # 检查是否检查了返回值
            if 'require' not in stripped and 'if' not in stripped and '=' not in stripped:
                issues.append({
                    'severity': 'MEDIUM',
                    'title': '外部调用返回值未检查',
                    'description': '.call() 等外部调用的返回值应该被检查',
                    'line': i,
                    'recommendation': '检查外部调用的返回值，确保调用成功'
                })
    
    return issues


def _analyze_mint_functionality(lines: List[str]) -> Optional[Dict[str, Any]]:
    """分析mint功能：形式、最大值限制、一次性vs运行态铸造"""
    mint_info = {
        "has_mint": False,
        "mint_in_constructor": False,
        "mint_function_exists": False,
        "has_max_supply": False,
        "max_supply_value": None,
        "mint_function_line": None,
        "constructor_mint_line": None,
        "mint_access_control": False
    }
    
    in_constructor = False
    in_mint_function = False
    constructor_line = 0
    mint_function_line = 0
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测构造函数
        if re.search(r'constructor\s*\(', stripped):
            in_constructor = True
            constructor_line = i
        
        # 检测mint函数
        if re.search(r'function\s+mint', stripped, re.IGNORECASE):
            mint_info["has_mint"] = True
            mint_info["mint_function_exists"] = True
            mint_function_line = i
            mint_info["mint_function_line"] = i
            in_mint_function = True
            
            # 检查权限控制
            if 'onlyOwner' in stripped or 'onlyRole' in stripped or 'modifier' in stripped:
                mint_info["mint_access_control"] = True
        
        # 在构造函数中查找mint调用
        if in_constructor:
            if 'mint(' in stripped or '_mint(' in stripped:
                mint_info["has_mint"] = True
                mint_info["mint_in_constructor"] = True
                mint_info["constructor_mint_line"] = i
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                in_constructor = False
        
        # 在mint函数中查找权限控制
        if in_mint_function:
            if 'onlyOwner' in stripped or 'onlyRole' in stripped or 'require(' in stripped:
                if 'msg.sender' in stripped or 'owner' in stripped.lower():
                    mint_info["mint_access_control"] = True
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                in_mint_function = False
        
        # 查找最大供应量限制
        if re.search(r'(maxSupply|max_supply|MAX_SUPPLY|cap|CAP)', stripped, re.IGNORECASE):
            mint_info["has_max_supply"] = True
            # 尝试提取数值
            num_match = re.search(r'(\d+)', stripped)
            if num_match:
                mint_info["max_supply_value"] = num_match.group(1)
        
        # 查找totalSupply检查
        if 'totalSupply' in stripped and ('<=' in stripped or '<' in stripped or 'require' in stripped):
            mint_info["has_max_supply"] = True
    
    if not mint_info["has_mint"]:
        return None
    
    # 构建分析结果
    mint_type = "未知"
    if mint_info["mint_in_constructor"] and not mint_info["mint_function_exists"]:
        mint_type = "仅部署时一次性铸造"
    elif mint_info["mint_in_constructor"] and mint_info["mint_function_exists"]:
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
    elif mint_info["constructor_mint_line"]:
        line_num = mint_info["constructor_mint_line"]
    else:
        line_num = 0
    
    severity = "HIGH" if not mint_info["mint_access_control"] else "INFO"
    
    return {
        "severity": severity,
        "title": "Mint功能分析",
        "description": description,
        "line": line_num,
        "mint_analysis": {
            "mint_type": mint_type,
            "max_supply": max_supply_info,
            "access_control": access_control_info,
            "has_max_supply": mint_info["has_max_supply"],
            "mint_in_constructor": mint_info["mint_in_constructor"],
            "mint_function_exists": mint_info["mint_function_exists"]
        },
        "recommendation": "确认mint权限控制和最大供应量限制是否符合预期"
    }


def format_pattern_scan_results(issues: List[Dict[str, Any]]) -> str:
    """
    格式化模式匹配扫描结果
    """
    if not issues:
        return """
╔══════════════════════════════════════════════════════════════════════════════╗
║              模式匹配安全扫描结果                                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  未检测到常见的安全问题模式                                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    
    # 按严重程度分类
    critical = [i for i in issues if i.get('severity') == 'CRITICAL']
    high = [i for i in issues if i.get('severity') == 'HIGH']
    medium = [i for i in issues if i.get('severity') == 'MEDIUM']
    low = [i for i in issues if i.get('severity') == 'LOW']
    
    output_lines = []
    output_lines.append("")
    output_lines.append("╔══════════════════════════════════════════════════════════════════════════════╗")
    output_lines.append("║              模式匹配安全扫描结果                                        ║")
    output_lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
    output_lines.append(f"║  总问题数: {len(issues)}")
    output_lines.append(f"║  严重 (CRITICAL): {len(critical)}")
    output_lines.append(f"║  高危 (HIGH): {len(high)}")
    output_lines.append(f"║  中危 (MEDIUM): {len(medium)}")
    output_lines.append(f"║  低危 (LOW): {len(low)}")
    output_lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
    output_lines.append("")
    
    # 提取mint分析信息（如果有）
    mint_analysis = None
    other_issues = []
    for issue in issues:
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
    all_issues = [i for i in (critical + high + medium + low) if i.get('title') != 'Mint功能分析']
    
    for idx, issue in enumerate(all_issues, 1):
        severity = issue.get('severity', 'UNKNOWN')
        output_lines.append(f"【问题 #{idx}】{severity} - {issue.get('title', '未知问题')}")
        output_lines.append("─" * 80)
        output_lines.append(f"  描述: {issue.get('description', '无描述')}")
        output_lines.append(f"  位置: 第 {issue.get('line', '?')} 行")
        if issue.get('recommendation'):
            output_lines.append(f"  建议: {issue.get('recommendation')}")
        output_lines.append("")
    
    return "\n".join(output_lines)

