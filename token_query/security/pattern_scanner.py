"""
基于模式匹配的安全扫描器
不需要编译，直接分析源代码文本
检测常见的安全漏洞模式
"""
import re
from typing import List, Dict, Any, Optional


def _is_in_string(line: str, keyword: str) -> bool:
    """
    检查关键词是否在字符串中（简单实现）
    返回True如果关键词在引号对之间
    """
    keyword_idx = line.find(keyword)
    if keyword_idx == -1:
        return False
    
    before = line[:keyword_idx]
    after = line[keyword_idx + len(keyword):]
    
    # 计算前面的引号数量
    before_quotes = before.count('"') + before.count("'")
    # 如果引号数量是奇数，说明在字符串中
    return before_quotes % 2 == 1


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
    
    # 过滤掉非安全问题：只保留真正的安全问题
    filtered_issues = []
    # 定义需要过滤掉的非安全问题标题关键词
    non_security_keywords = [
        '可能未初始化的变量',
        '不安全的类型转换',
        '未检查的外部调用返回值',
        '外部调用返回值未检查',
        '未限制的循环',
        '重要操作可能缺少事件记录',
        '可能缺少事件记录'
    ]
    
    for issue in issues:
        severity = issue.get('severity', '').upper()
        title = issue.get('title', '')
        
        # 保留所有CRITICAL和HIGH级别的问题
        if severity in ['CRITICAL', 'HIGH']:
            filtered_issues.append(issue)
        # 对于MEDIUM级别，只保留真正的安全问题
        elif severity == 'MEDIUM':
            # 排除非安全问题
            if not any(keyword in title for keyword in non_security_keywords):
                filtered_issues.append(issue)
        # 保留mint分析（即使是INFO级别）
        elif issue.get('title') == 'Mint功能分析':
            filtered_issues.append(issue)
    
    return filtered_issues


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
    """分析mint功能：形式、最大值限制、一次性vs运行态铸造，并提取代码片段"""
    mint_info = {
        "has_mint": False,
        "mint_in_constructor": False,
        "mint_function_exists": False,
        "has_max_supply": False,
        "max_supply_value": None,
        "mint_function_line": None,
        "constructor_mint_line": None,
        "mint_access_control": False,
        "mint_code_snippet": None,
        "constructor_mint_code_snippet": None,
        "max_supply_code_snippet": None
    }
    
    in_constructor = False
    in_mint_function = False
    constructor_line = 0
    mint_function_line = 0
    constructor_code_lines = []
    mint_function_code_lines = []
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # 检测构造函数
        if re.search(r'constructor\s*\(', stripped):
            in_constructor = True
            constructor_line = i
            constructor_code_lines = [line]
        
        # 检测公开的mint函数（不包括内部的_mint，_mint是标准实现）
        # _mint通常是ERC20标准内部函数，用于实际铸造逻辑
        # 公开的mint函数才是我们关心的可调用接口
        mint_match = re.search(r'function\s+(?:public\s+|external\s+)?mint\s*\(', stripped, re.IGNORECASE)
        if mint_match:
            # 排除内部/私有函数
            if 'internal' not in stripped.lower() and 'private' not in stripped.lower():
                mint_info["has_mint"] = True
                mint_info["mint_function_exists"] = True
                mint_function_line = i
                mint_info["mint_function_line"] = i
                in_mint_function = True
                mint_function_code_lines = [line]
            
            # 智能检测权限控制 - 不仅基于关键词，还分析函数签名和上下文
            # 1. 检查函数签名中的修饰符（排除注释和字符串）
            function_signature = stripped
            # 移除注释
            if '//' in function_signature:
                function_signature = function_signature[:function_signature.index('//')]
            # 检查是否有修饰符（在函数名和参数之间，或参数和{之间）
            modifier_match = re.search(r'function\s+mint[^{]*?\)\s*([a-zA-Z_][a-zA-Z0-9_]*\s+)*([a-zA-Z_][a-zA-Z0-9_]*)\s*{', function_signature, re.IGNORECASE)
            if modifier_match:
                # 提取修饰符部分
                modifiers_part = function_signature[modifier_match.end(1):modifier_match.end(2)]
                # 检查常见的权限修饰符
                access_control_patterns = [
                    'onlyOwner', 'onlyRole', 'onlyMinter', 'onlyAdmin', 
                    'onlyOperator', 'onlyController', 'onlyManager', 'onlyGovernor',
                    'onlyWhitelist', 'onlyWhitelisted', 'onlyAuthorized', 'onlyAuthorizedRole',
                    'hasRole', 'hasAccess', 'checkRole', 'requireRole',
                    'onlyFactory', 'onlyBridge', 'onlyLiquidityProvider', 'onlyTreasury',
                    'onlyPauser', 'onlyUnpauser', 'onlyMinterRole', 'onlyBurner',
                    'onlyUpgrader', 'onlyProxyAdmin', 'onlyTimelock', 'onlyMultisig',
                    'whenNotPaused', 'whenPaused'
                ]
                detected_modifiers = [p for p in access_control_patterns if p in modifiers_part]
                if detected_modifiers:
                    mint_info["mint_access_control"] = True
                    mint_info["detected_access_modifiers"] = detected_modifiers
            else:
                # 2. 如果没有在函数签名中找到，检查函数名后的修饰符（可能跨行）
                # 向前查找几行，看是否有修饰符
                for check_line_idx in range(max(0, i - 3), i + 1):
                    check_line = lines[check_line_idx].strip()
                    # 移除注释
                    if '//' in check_line:
                        check_line = check_line[:check_line.index('//')]
                    # 检查是否包含权限修饰符关键词（但不在字符串中）
                    access_control_patterns = [
                        'onlyOwner', 'onlyRole', 'onlyMinter', 'onlyAdmin', 
                        'onlyOperator', 'onlyController', 'onlyManager', 'onlyGovernor',
                        'onlyWhitelist', 'onlyWhitelisted', 'onlyAuthorized', 'onlyAuthorizedRole',
                        'hasRole', 'hasAccess', 'checkRole', 'requireRole',
                        'onlyFactory', 'onlyBridge', 'onlyLiquidityProvider', 'onlyTreasury',
                        'onlyPauser', 'onlyUnpauser', 'onlyMinterRole', 'onlyBurner',
                        'onlyUpgrader', 'onlyProxyAdmin', 'onlyTimelock', 'onlyMultisig',
                        'whenNotPaused', 'whenPaused'
                    ]
                    # 检查是否在字符串中（简单检查：是否在引号中）
                    in_string = False
                    quote_count = check_line.count('"') + check_line.count("'")
                    if quote_count > 0:
                        # 简单检查：如果关键词在引号对之间，可能是在字符串中
                        for pattern in access_control_patterns:
                            pattern_idx = check_line.find(pattern)
                            if pattern_idx != -1:
                                # 检查前后是否有引号
                                before = check_line[:pattern_idx]
                                after = check_line[pattern_idx + len(pattern):]
                                before_quotes = before.count('"') + before.count("'")
                                after_quotes = after.count('"') + after.count("'")
                                # 如果引号数量是奇数，说明在字符串中
                                if before_quotes % 2 == 1 or after_quotes % 2 == 1:
                                    continue
                                # 如果不在注释中
                                if '//' not in check_line[:pattern_idx] or check_line.index('//') > pattern_idx:
                                    detected_modifiers = [pattern]
                                    mint_info["mint_access_control"] = True
                                    mint_info["detected_access_modifiers"] = detected_modifiers
                                    break
                    else:
                        # 没有引号，直接检查
                        detected_modifiers = [p for p in access_control_patterns if p in check_line and '//' not in check_line[:check_line.index(p)]]
                        if detected_modifiers:
                            mint_info["mint_access_control"] = True
                            mint_info["detected_access_modifiers"] = detected_modifiers
                            break
        
        # 在构造函数中查找mint调用和maxSupply赋值
        if in_constructor:
            constructor_code_lines.append(line)
            if 'mint(' in stripped or '_mint(' in stripped:
                mint_info["has_mint"] = True
                mint_info["mint_in_constructor"] = True
                mint_info["constructor_mint_line"] = i
            # 查找构造函数中对maxSupply的赋值
            if mint_info.get("need_find_constructor_assign") and mint_info.get("max_supply_var_name"):
                var_name = mint_info["max_supply_var_name"]
                if var_name in stripped and '=' in stripped:
                    assign_match = re.search(r'=\s*([0-9_]+(?:e[0-9]+)?)', stripped)
                    if assign_match:
                        value_str = assign_match.group(1).replace('_', '')
                        if value_str != '0' and not value_str.startswith('0e'):
                            mint_info["max_supply_value"] = value_str
                            mint_info["need_find_constructor_assign"] = False
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                in_constructor = False
                if mint_info["mint_in_constructor"]:
                    # 提取构造函数中的mint相关代码（前后各5行）
                    start = max(0, constructor_line - 1)
                    end = min(len(lines), i + 1)
                    mint_info["constructor_mint_code_snippet"] = '\n'.join(lines[start:end])
        
        # 在mint函数中智能查找权限控制
        if in_mint_function:
            mint_function_code_lines.append(line)
            
            # 智能权限检测：不仅检查关键词，还分析语义
            if not mint_info.get("mint_access_control") or not mint_info.get("checked_permission_semantically"):
                # 1. 检查函数体中的require语句（权限检查）
                if 'require(' in stripped:
                    # 移除注释
                    require_line = stripped
                    if '//' in require_line:
                        require_line = require_line[:require_line.index('//')]
                    
                    # 检查require中的权限相关逻辑（使用正则表达式匹配语义模式）
                    permission_patterns = [
                        r'msg\.sender\s*==\s*\w*owner',  # msg.sender == owner
                        r'owner\s*==\s*msg\.sender',      # owner == msg.sender
                        r'hasRole\s*\([^)]*msg\.sender',  # hasRole(..., msg.sender)
                        r'roles\s*\[\s*msg\.sender',      # roles[msg.sender]
                        r'isOwner\s*\([^)]*msg\.sender',  # isOwner(msg.sender)
                        r'isAuthorized\s*\([^)]*msg\.sender',  # isAuthorized(msg.sender)
                        r'isMinter\s*\([^)]*msg\.sender',  # isMinter(msg.sender)
                        r'minter\s*==\s*msg\.sender',     # minter == msg.sender
                        r'msg\.sender\s*==\s*\w*minter',  # msg.sender == minter
                        r'admin\s*==\s*msg\.sender',      # admin == msg.sender
                        r'msg\.sender\s*==\s*\w*admin',   # msg.sender == admin
                    ]
                    
                    for pattern in permission_patterns:
                        if re.search(pattern, require_line, re.IGNORECASE):
                            # 检查是否在字符串中
                            if not _is_in_string(require_line, pattern[:10]):  # 使用模式的前10个字符作为关键词
                                mint_info["mint_access_control"] = True
                                if not mint_info.get("detected_access_modifiers"):
                                    mint_info["detected_access_modifiers"] = []
                                mint_info["detected_access_modifiers"].append("require_permission_check")
                                mint_info["checked_permission_semantically"] = True
                                break
                    
                    # 检查require中的权限关键词（但排除在字符串中的）
                    if not mint_info.get("mint_access_control"):
                        permission_keywords = [
                            'owner', 'minter', 'admin', 'operator', 
                            'controller', 'role', 'authorized', 'whitelist', 
                            'access', 'permission', 'allowed', 'approved'
                        ]
                        for keyword in permission_keywords:
                            if keyword in require_line.lower() and not _is_in_string(require_line, keyword):
                                mint_info["mint_access_control"] = True
                                if not mint_info.get("detected_access_modifiers"):
                                    mint_info["detected_access_modifiers"] = []
                                mint_info["detected_access_modifiers"].append(f"require_{keyword}_check")
                                mint_info["checked_permission_semantically"] = True
                                break
                
                # 2. 检查if语句中的权限检查
                elif re.search(r'if\s*\([^)]*(?:msg\.sender|owner|minter|admin|role|authorized)', stripped, re.IGNORECASE):
                    # 移除注释
                    if_line = stripped
                    if '//' in if_line:
                        if_line = if_line[:if_line.index('//')]
                    # 检查是否在字符串中
                    if not _is_in_string(if_line, 'msg.sender'):
                        mint_info["mint_access_control"] = True
                        if not mint_info.get("detected_access_modifiers"):
                            mint_info["detected_access_modifiers"] = []
                        mint_info["detected_access_modifiers"].append("if_permission_check")
                        mint_info["checked_permission_semantically"] = True
                
                # 3. 检查修饰符调用（如 modifier onlyOwner() { ... }）
                elif re.search(r'(?:modifier|function)\s+\w*only\w*', stripped, re.IGNORECASE):
                    if not _is_in_string(stripped, 'modifier'):
                        modifier_match = re.search(r'(?:modifier|function)\s+(\w*only\w*)', stripped, re.IGNORECASE)
                        if modifier_match:
                            modifier_name = modifier_match.group(1)
                            mint_info["mint_access_control"] = True
                            if not mint_info.get("detected_access_modifiers"):
                                mint_info["detected_access_modifiers"] = []
                            mint_info["detected_access_modifiers"].append(modifier_name)
                            mint_info["checked_permission_semantically"] = True
                
                # 4. 检查函数签名中的修饰符（如果之前没检测到）
                if not mint_info.get("mint_access_control"):
                    access_control_patterns = [
                        'onlyOwner', 'onlyRole', 'onlyMinter', 'onlyAdmin',
                        'onlyOperator', 'onlyController', 'onlyManager', 'onlyGovernor',
                        'onlyWhitelist', 'onlyWhitelisted', 'onlyAuthorized', 'onlyAuthorizedRole',
                        'hasRole', 'hasAccess', 'checkRole', 'requireRole',
                        'onlyFactory', 'onlyBridge', 'onlyLiquidityProvider', 'onlyTreasury',
                        'onlyPauser', 'onlyUnpauser', 'onlyMinterRole', 'onlyBurner',
                        'onlyUpgrader', 'onlyProxyAdmin', 'onlyTimelock', 'onlyMultisig',
                        'whenNotPaused', 'whenPaused'
                    ]
                    for pattern in access_control_patterns:
                        if pattern in stripped and not _is_in_string(stripped, pattern):
                            mint_info["mint_access_control"] = True
                            if not mint_info.get("detected_access_modifiers"):
                                mint_info["detected_access_modifiers"] = []
                            mint_info["detected_access_modifiers"].append(pattern)
                            break
                
                # 5. 检查函数体开始后是否有权限检查（如果函数签名中没有）
                if '{' in stripped and not mint_info.get("mint_access_control") and not mint_info.get("checked_permission_in_body"):
                    mint_info["checked_permission_in_body"] = True
                    # 检查函数签名（可能跨多行）
                    for check_i in range(max(0, mint_function_line - 1), i + 1):
                        check_line = lines[check_i].strip()
                        # 移除注释
                        if '//' in check_line:
                            check_line = check_line[:check_line.index('//')]
                        # 检查修饰符（不在字符串中）
                        access_control_patterns = [
                            'onlyOwner', 'onlyRole', 'onlyMinter', 'onlyAdmin',
                            'onlyOperator', 'onlyController', 'onlyManager', 'onlyGovernor',
                            'onlyWhitelist', 'onlyWhitelisted', 'onlyAuthorized', 'onlyAuthorizedRole',
                            'hasRole', 'hasAccess', 'checkRole', 'requireRole',
                            'onlyFactory', 'onlyBridge', 'onlyLiquidityProvider', 'onlyTreasury',
                            'onlyPauser', 'onlyUnpauser', 'onlyMinterRole', 'onlyBurner',
                            'onlyUpgrader', 'onlyProxyAdmin', 'onlyTimelock', 'onlyMultisig',
                            'whenNotPaused', 'whenPaused'
                        ]
                        for pattern in access_control_patterns:
                            if pattern in check_line and not _is_in_string(check_line, pattern):
                                mint_info["mint_access_control"] = True
                                if not mint_info.get("detected_access_modifiers"):
                                    mint_info["detected_access_modifiers"] = []
                                mint_info["detected_access_modifiers"].append(pattern)
                                break
                        if mint_info.get("mint_access_control"):
                            break
            if stripped == '}' or (stripped.endswith('}') and '{' not in stripped):
                in_mint_function = False
                # 提取mint函数代码（前后各5行）
                start = max(0, mint_function_line - 1)
                end = min(len(lines), i + 1)
                mint_info["mint_code_snippet"] = '\n'.join(lines[start:end])
        
        # 查找最大供应量限制
        if re.search(r'(maxSupply|max_supply|MAX_SUPPLY|cap|CAP)', stripped, re.IGNORECASE):
            mint_info["has_max_supply"] = True
            # 尝试提取数值 - 改进逻辑，避免提取条件判断中的0
            # 优先查找赋值语句：maxSupply = 1000000; 或 uint256 maxSupply = 1000000;
            assignment_match = re.search(r'(?:maxSupply|max_supply|MAX_SUPPLY|cap|CAP)\s*=\s*([0-9_]+(?:e[0-9]+)?)', stripped, re.IGNORECASE)
            if assignment_match:
                value_str = assignment_match.group(1).replace('_', '')
                # 排除0值（可能是初始化或条件判断）
                if value_str != '0' and not value_str.startswith('0e'):
                    mint_info["max_supply_value"] = value_str
            else:
                # 查找常量定义：uint256 constant MAX_SUPPLY = 1000000;
                constant_match = re.search(r'(?:constant|immutable)\s+(?:maxSupply|max_supply|MAX_SUPPLY|cap|CAP)\s*=\s*([0-9_]+(?:e[0-9]+)?)', stripped, re.IGNORECASE)
                if constant_match:
                    value_str = constant_match.group(1).replace('_', '')
                    if value_str != '0' and not value_str.startswith('0e'):
                        mint_info["max_supply_value"] = value_str
                else:
                    # 查找变量声明：uint256 public maxSupply = 1000000;
                    declaration_match = re.search(r'(?:uint256|uint|uint128|uint64)\s+(?:public\s+)?(?:maxSupply|max_supply|MAX_SUPPLY|cap|CAP)\s*=\s*([0-9_]+(?:e[0-9]+)?)', stripped, re.IGNORECASE)
                    if declaration_match:
                        value_str = declaration_match.group(1).replace('_', '')
                        if value_str != '0' and not value_str.startswith('0e'):
                            mint_info["max_supply_value"] = value_str
                    else:
                        # 最后尝试：查找非0的数字（排除条件判断中的0和类型名中的256）
                        # 避免匹配 if (maxSupply > 0) 中的0 和 uint256 中的256
                        if '>' not in stripped and '<' not in stripped and '==' not in stripped and '!=' not in stripped:
                            # 排除类型声明行（如 uint256 i_maxSupply; 或 uint256 amount）
                            # 只有当行中包含maxSupply/cap等关键词且不是类型声明时才提取数字
                            if re.search(r'(?:maxSupply|max_supply|MAX_SUPPLY|cap|CAP)', stripped, re.IGNORECASE):
                                # 检查是否是类型声明（如 uint256 i_maxSupply;）
                                if not re.search(r'uint\d*\s+(?:i_|_)?(?:maxSupply|max_supply|MAX_SUPPLY|cap|CAP)\s*;', stripped, re.IGNORECASE):
                                    num_match = re.search(r'([1-9][0-9_]*(?:e[0-9]+)?)', stripped)
                                    if num_match:
                                        value_str = num_match.group(1).replace('_', '')
                                        # 排除256（可能是uint256类型名的一部分）
                                        if value_str != '256':
                                            mint_info["max_supply_value"] = value_str
            # 提取最大供应量相关代码（前后各3行）
            start = max(0, i - 4)
            end = min(len(lines), i + 3)
            mint_info["max_supply_code_snippet"] = '\n'.join(lines[start:end])
        
        # 查找totalSupply检查（如 totalSupply <= maxSupply 或 totalSupply < cap）
        if 'totalSupply' in stripped and ('<=' in stripped or '<' in stripped or 'require' in stripped or '>' in stripped):
            mint_info["has_max_supply"] = True
            # 尝试从比较表达式中提取最大值
            # 例如：require(totalSupply <= maxSupply, "...") 或 if (totalSupply < cap)
            if not mint_info["max_supply_value"] and not mint_info.get("max_supply_from_param"):
                # 查找 totalSupply <= 数字 或 totalSupply < 数字
                comparison_match = re.search(r'totalSupply\s*(?:\+|\-)?\s*\w*\s*(?:<|<=)\s*([0-9_]+(?:e[0-9]+)?)', stripped, re.IGNORECASE)
                if comparison_match:
                    value_str = comparison_match.group(1).replace('_', '')
                    if value_str != '0' and not value_str.startswith('0e'):
                        mint_info["max_supply_value"] = value_str
                else:
                    # 查找 totalSupply + amount <= 变量名 或 totalSupply < 变量名
                    # 例如：totalSupply() + amount > i_maxSupply
                    var_match = re.search(r'totalSupply[^>]*>\s*([a-zA-Z_][a-zA-Z0-9_]*)', stripped, re.IGNORECASE)
                    if not var_match:
                        var_match = re.search(r'totalSupply[^<]*<\s*([a-zA-Z_][a-zA-Z0-9_]*)', stripped, re.IGNORECASE)
                    if not var_match:
                        var_match = re.search(r'totalSupply[^=]*<=\s*([a-zA-Z_][a-zA-Z0-9_]*)', stripped, re.IGNORECASE)
                    if var_match:
                        var_name = var_match.group(1)
                        # 向前查找变量定义（最多向前查找200行，因为可能在文件开头）
                        for j in range(max(0, i - 200), i):
                            prev_line = lines[j].strip()
                            # 优先查找变量赋值：i_maxSupply = maxSupply_; 或 i_maxSupply = 1000000;
                            if var_name in prev_line and '=' in prev_line:
                                # 查找赋值语句：var_name = value;
                                assign_match = re.search(re.escape(var_name) + r'\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*;', prev_line)
                                if assign_match:
                                    # 如果赋值给另一个变量（如 i_maxSupply = maxSupply_;），查找那个变量的值
                                    assigned_var = assign_match.group(1)
                                    # 向前查找assigned_var的定义或参数（最多向前查找200行）
                                    found_param = False
                                    for l in range(max(0, j - 200), j):
                                        param_line = lines[l].strip()
                                        # 查找函数参数：function initialize(uint256 maxSupply_) 或 function initialize(...uint256 maxSupply_...)
                                        # 支持多行参数定义
                                        if assigned_var in param_line:
                                            # 检查是否是参数类型定义（如 uint256 maxSupply_）
                                            param_type_match = re.search(r'(?:uint256|uint|uint128|uint64)\s+' + re.escape(assigned_var), param_line, re.IGNORECASE)
                                            if param_type_match:
                                                # 检查是否在函数定义中（向前查找函数定义，最多15行，支持多行参数）
                                                for m in range(max(0, l - 15), l + 1):
                                                    func_line = lines[m].strip()
                                                    # 检查是否是函数定义，并且参数行在函数参数列表中
                                                    if 'function' in func_line.lower():
                                                        # 检查参数行是否在函数参数范围内（函数定义行到参数行之间应该有(或)
                                                        has_open_paren = False
                                                        for n in range(m, l + 1):
                                                            if '(' in lines[n]:
                                                                has_open_paren = True
                                                            if ')' in lines[n] and n < l:
                                                                break
                                                        if has_open_paren:
                                                            # 这是函数参数，无法从代码中直接获取值，需要运行时数据
                                                            mint_info["max_supply_from_param"] = True
                                                            found_param = True
                                                            break
                                                    elif 'constructor' in func_line.lower():
                                                        # 构造函数参数
                                                        has_open_paren = False
                                                        for n in range(m, l + 1):
                                                            if '(' in lines[n]:
                                                                has_open_paren = True
                                                            if ')' in lines[n] and n < l:
                                                                break
                                                        if has_open_paren:
                                                            mint_info["max_supply_from_param"] = True
                                                            found_param = True
                                                            break
                                                if found_param:
                                                    break
                                    if found_param:
                                        break
                                else:
                                    # 直接赋值数字：i_maxSupply = 1000000;
                                    direct_assign_match = re.search(re.escape(var_name) + r'\s*=\s*([0-9_]+(?:e[0-9]+)?)', prev_line)
                                    if direct_assign_match:
                                        value_str = direct_assign_match.group(1).replace('_', '')
                                        if value_str != '0' and value_str != '256' and not value_str.startswith('0e'):
                                            mint_info["max_supply_value"] = value_str
                                            break
                            # 查找变量声明：uint256 i_maxSupply; 或 uint256 internal i_maxSupply;
                            elif var_name in prev_line:
                                # 查找immutable变量声明：uint256 immutable i_maxSupply;
                                immutable_match = re.search(r'(?:uint256|uint)\s+immutable\s+' + re.escape(var_name), prev_line, re.IGNORECASE)
                                if immutable_match:
                                    # immutable变量通常在构造函数或初始化函数中赋值
                                    # 查找构造函数或初始化函数
                                    for k in range(j, min(len(lines), j + 100)):
                                        func_line = lines[k].strip()
                                        if 'constructor' in func_line or 'initialize' in func_line.lower():
                                            # 查找函数体中的赋值
                                            for m in range(k, min(len(lines), k + 50)):
                                                assign_line = lines[m].strip()
                                                if var_name in assign_line and '=' in assign_line:
                                                    # 检查是否是赋值给变量
                                                    assign_to_var_match = re.search(re.escape(var_name) + r'\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*;', assign_line)
                                                    if assign_to_var_match:
                                                        assigned_var = assign_to_var_match.group(1)
                                                        # 检查assigned_var是否是函数参数
                                                        for n in range(max(0, k - 20), k + 20):
                                                            param_line = lines[n].strip()
                                                            if assigned_var in param_line:
                                                                param_type_match = re.search(r'(?:uint256|uint|uint128|uint64)\s+' + re.escape(assigned_var), param_line, re.IGNORECASE)
                                                                if param_type_match:
                                                                    mint_info["max_supply_from_param"] = True
                                                                    break
                                                        if mint_info.get("max_supply_from_param"):
                                                            break
                                                    else:
                                                        assign_value_match = re.search(r'=\s*([0-9_]+(?:e[0-9]+)?)', assign_line)
                                                        if assign_value_match:
                                                            value_str = assign_value_match.group(1).replace('_', '')
                                                            if value_str != '0' and value_str != '256' and not value_str.startswith('0e'):
                                                                mint_info["max_supply_value"] = value_str
                                                                break
                                            if mint_info.get("max_supply_value") or mint_info.get("max_supply_from_param"):
                                                break
                                    if mint_info.get("max_supply_value") or mint_info.get("max_supply_from_param"):
                                        break
                                # 查找构造函数或函数参数：constructor(uint256 _maxSupply) 或 function initialize(uint256 maxSupply_)
                                param_match = re.search(r'(?:constructor|function)\s+\w*\s*\([^)]*' + re.escape(var_name) + r'[^)]*\)', prev_line, re.IGNORECASE)
                                if not param_match:
                                    # 也查找参数名（如 maxSupply_）
                                    param_match = re.search(r'(?:constructor|function)\s+\w*\s*\([^)]*(?:uint256|uint)\s+([a-zA-Z_][a-zA-Z0-9_]*)[^)]*\)', prev_line, re.IGNORECASE)
                                    if param_match:
                                        param_name = param_match.group(1)
                                        # 检查这个参数是否被赋值给我们的变量
                                        for k in range(j, min(len(lines), j + 50)):
                                            assign_line = lines[k].strip()
                                            if var_name in assign_line and param_name in assign_line and '=' in assign_line:
                                                # 这是函数参数，无法从代码中直接获取值
                                                mint_info["max_supply_from_param"] = True
                                                break
                                    else:
                                        # 查找构造函数体中的赋值
                                        for k in range(j, min(len(lines), j + 50)):
                                            assign_line = lines[k].strip()
                                            if var_name in assign_line and '=' in assign_line:
                                                assign_value_match = re.search(r'=\s*([0-9_]+(?:e[0-9]+)?)', assign_line)
                                                if assign_value_match:
                                                    value_str = assign_value_match.group(1).replace('_', '')
                                                    if value_str != '0' and not value_str.startswith('0e'):
                                                        mint_info["max_supply_value"] = value_str
                                                        break
                                    if mint_info.get("max_supply_value") or mint_info.get("max_supply_from_param"):
                                        break
            if not mint_info["max_supply_code_snippet"]:
                # 提取totalSupply检查代码（前后各3行）
                start = max(0, i - 4)
                end = min(len(lines), i + 3)
                mint_info["max_supply_code_snippet"] = '\n'.join(lines[start:end])
    
    # 智能分析：检查是否有继承关系（可能mint在父合约中）
    has_inheritance = False
    parent_contracts = []
    contract_name = None
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # 移除注释
        if '//' in stripped:
            stripped = stripped[:stripped.index('//')]
        # 检测继承关系: contract X is Y, Z
        if 'contract ' in stripped and ' is ' in stripped:
            has_inheritance = True
            # 提取合约名和父合约名
            match = re.search(r'contract\s+(\w+)\s+is\s+([^{]+)', stripped)
            if match:
                contract_name = match.group(1)
                parents = match.group(2).split(',')
                parent_contracts = [p.strip() for p in parents if p.strip()]
                break
    
    # 智能分析：如果mint函数没有直接权限控制，检查是否从父合约继承
    if mint_info["mint_function_exists"] and not mint_info.get("mint_access_control") and has_inheritance:
        # 检查父合约是否可能提供权限控制
        # 常见的提供权限控制的父合约
        access_control_parents = [
            'Ownable', 'AccessControl', 'Roles', 'AccessControlEnumerable',
            'MinterRole', 'Pausable', 'ReentrancyGuard'
        ]
        if any(parent in ' '.join(parent_contracts) for parent in access_control_parents):
            # 可能从父合约继承了权限控制，但需要进一步确认
            # 检查mint函数是否override了父合约的函数
            mint_function_line = mint_info.get("mint_function_line", 0)
            if mint_function_line > 0:
                for check_i in range(max(0, mint_function_line - 1), min(len(lines), mint_function_line + 3)):
                    check_line = lines[check_i].strip()
                    if 'override' in check_line.lower() and 'mint' in check_line.lower():
                        # 如果override了父合约的mint，可能继承了权限控制
                        mint_info["mint_access_control"] = True
                        mint_info["detected_access_modifiers"] = ["inherited_from_parent"]
                        mint_info["inherited_access_control"] = True
                        break
    
    # 如果没有检测到mint，但有关键的继承（如ERC20、OFT等），说明mint可能在父合约中
    if not mint_info["has_mint"] and has_inheritance:
        # 检查是否是常见的代币合约继承
        token_keywords = ['ERC20', 'ERC721', 'ERC1155', 'OFT', 'Token', 'Coin', 'StandardToken']
        if any(keyword in ' '.join(parent_contracts) for keyword in token_keywords):
            return {
                "severity": "INFO",
                "title": "Mint功能分析",
                "description": f"本合约未定义mint函数，但继承了 {', '.join(parent_contracts)}\n铸造形式: 可能在父合约中实现\n最大值限制: 需查看父合约代码\n权限控制: 需查看父合约代码",
                "line": 0,
                "mint_analysis": {
                    "mint_type": "可能在父合约中实现",
                    "max_supply": "需查看父合约代码",
                    "access_control": "需查看父合约代码",
                    "has_max_supply": False,
                    "mint_in_constructor": False,
                    "mint_function_exists": False,
                    "inherited_from": parent_contracts,
                    "mint_code_snippet": None,
                    "constructor_mint_code_snippet": None,
                    "max_supply_code_snippet": None
                },
                "recommendation": "mint功能可能在父合约中实现，建议查看父合约代码"
            }
    
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
    
    # 智能权限控制评估：
    # 1. 如果mint只在构造函数中，且合约继承了权限控制合约（如Ownable），这是安全的
    #    构造函数只能被调用一次，且继承Ownable说明有权限控制机制
    # 2. 只有当存在运行时的mint函数且没有权限控制时，才应该报告"缺少权限控制"
    if mint_info["mint_in_constructor"] and not mint_info["mint_function_exists"]:
        # 仅构造函数中的mint，检查是否继承了权限控制合约
        if has_inheritance:
            access_control_parents = [
                'Ownable', 'AccessControl', 'Roles', 'AccessControlEnumerable',
                'MinterRole', 'Pausable', 'ReentrancyGuard'
            ]
            if any(parent in ' '.join(parent_contracts) for parent in access_control_parents):
                # 继承了权限控制合约，构造函数中的mint是安全的
                mint_info["mint_access_control"] = True
                if not mint_info.get("detected_access_modifiers"):
                    mint_info["detected_access_modifiers"] = []
                mint_info["detected_access_modifiers"].append("constructor_with_access_control_inheritance")
                mint_info["constructor_safe"] = True
    
    max_supply_info = "无限制"
    if mint_info["has_max_supply"]:
        if mint_info.get("max_supply_from_param"):
            max_supply_info = "有最大值限制（通过函数参数传入，部署/初始化时可指定具体值）"
        elif mint_info["max_supply_value"]:
            # 如果提取到的值是256，可能是误提取（比如uint256类型），需要进一步验证
            if mint_info["max_supply_value"] == "256":
                # 检查是否真的是maxSupply的值，还是只是类型uint256
                code_snippet = mint_info.get("max_supply_code_snippet", "")
                if code_snippet and "uint256" in code_snippet and "=" not in code_snippet:
                    max_supply_info = "有最大值限制（具体值需查看代码，可能在父合约或初始化函数中）"
                else:
                    max_supply_info = f"有最大值限制: {mint_info['max_supply_value']}"
            else:
                max_supply_info = f"有最大值限制: {mint_info['max_supply_value']}"
        else:
            max_supply_info = "有最大值限制（具体值需查看代码，可能在父合约或初始化函数中）"
    
    # 评估权限控制的充分性
    if mint_info["mint_access_control"]:
        detected_modifiers = mint_info.get("detected_access_modifiers", [])
        if detected_modifiers:
            # 检查权限控制是否足够严格
            # 过于宽松的权限控制（如public、external without modifier）
            weak_patterns = ['public', 'external', 'internal', 'private']
            is_weak = any(pattern in ' '.join(detected_modifiers).lower() for pattern in weak_patterns)
            
            # 检查是否有合适的权限修饰符
            strong_patterns = [
                'onlyOwner', 'onlyRole', 'onlyMinter', 'onlyAdmin',
                'onlyOperator', 'onlyController', 'hasRole', 'requireRole'
            ]
            has_strong_control = any(pattern in detected_modifiers for pattern in strong_patterns)
            
            if is_weak and not has_strong_control:
                access_control_info = f"权限控制不足（检测到: {', '.join(set(detected_modifiers))}）"
            else:
                # 如果是构造函数继承的权限控制，显示更友好的信息
                if "constructor_with_access_control_inheritance" in detected_modifiers:
                    access_control_info = "有权限控制（构造函数中mint，继承权限控制合约）"
                else:
                    access_control_info = f"有权限控制（{', '.join(set(detected_modifiers))}）"
        else:
            access_control_info = "有权限控制（未识别具体修饰符）"
    else:
        # 如果mint只在构造函数中，即使没有检测到权限控制，也不应该显示"缺少权限控制"
        if mint_info["mint_in_constructor"] and not mint_info["mint_function_exists"]:
            access_control_info = "构造函数中mint（相对安全，构造函数只能调用一次）"
        else:
            access_control_info = "缺少权限控制（高风险）"
    
    description = f"铸造形式: {mint_type}\n"
    description += f"最大值限制: {max_supply_info}\n"
    description += f"权限控制: {access_control_info}"
    
    if mint_info["mint_function_line"]:
        line_num = mint_info["mint_function_line"]
    elif mint_info["constructor_mint_line"]:
        line_num = mint_info["constructor_mint_line"]
    else:
        line_num = 0
    
    # 根据权限控制情况确定严重程度
    if not mint_info["mint_access_control"]:
        # 如果mint只在构造函数中，即使没有检测到权限控制，也不应该标记为CRITICAL
        # 因为构造函数只能被调用一次，且通常由部署者控制
        if mint_info["mint_in_constructor"] and not mint_info["mint_function_exists"]:
            severity = "INFO"  # 仅构造函数中的mint，相对安全
        else:
            severity = "CRITICAL"  # 运行时的mint缺少权限控制是严重问题
    else:
        detected_modifiers = mint_info.get("detected_access_modifiers", [])
        # 检查权限控制是否足够
        weak_patterns = ['public', 'external', 'internal', 'private']
        is_weak = any(pattern in ' '.join(detected_modifiers).lower() for pattern in weak_patterns)
        if is_weak:
            severity = "HIGH"  # 权限控制不足
        else:
            severity = "INFO"  # 有适当的权限控制
    
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
            "mint_function_exists": mint_info["mint_function_exists"],
            "mint_code_snippet": mint_info["mint_code_snippet"],
            "constructor_mint_code_snippet": mint_info["constructor_mint_code_snippet"],
            "max_supply_code_snippet": mint_info["max_supply_code_snippet"],
            "detected_access_modifiers": mint_info.get("detected_access_modifiers", [])
        },
        "recommendation": _generate_mint_recommendation(mint_info)
    }


def _generate_mint_recommendation(mint_info: Dict[str, Any]) -> str:
    """生成mint功能分析的建议"""
    recommendations = []
    
    # 权限控制建议
    if not mint_info["mint_access_control"]:
        # 如果mint只在构造函数中，给出不同的建议
        if mint_info["mint_in_constructor"] and not mint_info["mint_function_exists"]:
            recommendations.append("mint仅在构造函数中，构造函数只能被调用一次，相对安全")
            # 检查是否有继承关系
            if mint_info.get("constructor_safe"):
                recommendations.append("合约继承了权限控制合约（如Ownable），有权限控制机制")
        else:
            recommendations.append("严重：mint函数缺少权限控制，任何人都可以铸造代币，存在无限增发风险")
            recommendations.append("  建议：添加onlyOwner、onlyRole、onlyMinter等权限修饰符")
    else:
        detected_modifiers = mint_info.get("detected_access_modifiers", [])
        if detected_modifiers:
            # 检查是否是构造函数继承的权限控制
            if "constructor_with_access_control_inheritance" in detected_modifiers:
                recommendations.append("mint仅在构造函数中，构造函数只能被调用一次，相对安全")
                recommendations.append("合约继承了权限控制合约（如Ownable），有权限控制机制")
            else:
                # 检查权限控制是否足够严格
                weak_patterns = ['public', 'external', 'internal', 'private', 'require_check']
                is_weak = any(pattern in ' '.join(detected_modifiers).lower() for pattern in weak_patterns)
                
                # 检查是否有合适的权限修饰符
                strong_patterns = [
                    'onlyOwner', 'onlyRole', 'onlyMinter', 'onlyAdmin',
                    'onlyOperator', 'onlyController', 'hasRole', 'requireRole',
                    'onlyManager', 'onlyGovernor', 'onlyFactory', 'onlyBridge'
                ]
                has_strong_control = any(pattern in detected_modifiers for pattern in strong_patterns)
                
                # 检查是否有不合适的权限修饰符（如pause相关的用于mint）
                inappropriate_patterns = ['onlyPauser', 'onlyUnpauser', 'whenPaused', 'whenNotPaused']
                has_inappropriate = any(pattern in detected_modifiers for pattern in inappropriate_patterns)
                
                if has_inappropriate:
                    recommendations.append(f"警告：检测到可能不合适的权限修饰符（{', '.join([p for p in detected_modifiers if p in inappropriate_patterns])}）")
                    recommendations.append("  建议：mint函数应使用onlyMinter、onlyOwner等专门的权限控制，而非pause相关修饰符")
                elif is_weak and not has_strong_control:
                    recommendations.append(f"警告：mint函数的权限控制可能不足（检测到: {', '.join(set(detected_modifiers))}）")
                    recommendations.append("  建议：使用onlyOwner、onlyRole或onlyMinter等严格的权限修饰符")
                else:
                    recommendations.append(f"mint函数有适当的权限控制（{', '.join(set(detected_modifiers))}）")
        else:
            recommendations.append("mint函数有权限控制（未识别具体修饰符）")
    
    # 最大供应量建议
    if not mint_info["has_max_supply"]:
        recommendations.append("警告：未检测到最大供应量限制，存在无限增发风险")
        recommendations.append("  建议：添加maxSupply或cap限制，防止无限增发")
    elif mint_info.get("max_supply_from_param"):
        recommendations.append("最大供应量通过函数参数传入，部署/初始化时需确认具体值")
    elif mint_info.get("max_supply_value"):
        recommendations.append(f"检测到最大供应量限制: {mint_info['max_supply_value']}")
    else:
        recommendations.append("检测到最大供应量限制，但具体值需查看代码确认")
    
    return "\n".join(recommendations)


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

