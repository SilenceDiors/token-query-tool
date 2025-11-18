"""
简化扫描器：移除依赖项，只分析主合约
当完整扫描失败时的回退方案
"""
import re
from typing import Optional, Dict, Any


def extract_main_contract_without_dependencies(source_code: str) -> str:
    """
    从源代码中提取主合约，移除所有依赖项，创建一个最小可编译版本
    
    参数:
        source_code: Solidity 源代码
    
    返回:
        简化后的源代码（只包含主合约，无依赖项）
    """
    if not source_code or not isinstance(source_code, str):
        return source_code
    
    lines = source_code.split('\n')
    result_lines = []
    
    # 保留 SPDX 许可证标识符
    spdx_line = None
    pragma_line = None
    contract_name = None
    contract_start_idx = None
    
    # 第一步：找到关键信息
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('// SPDX-License-Identifier:'):
            spdx_line = line
        elif stripped.startswith('pragma solidity'):
            pragma_line = line
        elif 'contract ' in stripped and not contract_name:
            # 提取合约名
            contract_match = re.search(r'contract\s+(\w+)', stripped)
            if contract_match:
                contract_name = contract_match.group(1)
                contract_start_idx = i
                break
    
    if not contract_name:
        return source_code  # 如果找不到合约，返回原始代码
    
    # 第二步：构建简化版本
    if spdx_line:
        result_lines.append(spdx_line)
    if pragma_line:
        result_lines.append(pragma_line)
        result_lines.append('')
    
    # 第三步：提取合约内容（移除依赖项）
    in_contract = False
    brace_count = 0
    
    for i in range(contract_start_idx, len(lines)):
        line = lines[i]
        stripped = line.strip()
        
        # 跳过 import
        if stripped.startswith('import '):
            continue
        
        # 找到合约定义
        if 'contract ' in stripped and not in_contract:
            in_contract = True
            # 移除继承关系，只保留合约名
            result_lines.append(f'contract {contract_name} {{')
            brace_count = stripped.count('{') - stripped.count('}')
            continue
        
        if in_contract:
            brace_count += stripped.count('{') - stripped.count('}')
            
            # 移除构造函数中的依赖项调用
            if 'constructor' in stripped or (brace_count > 0 and any(keyword in stripped for keyword in ['OFT(', 'Ownable(', 'super.'])):
                # 如果是构造函数定义行，保留但简化
                if 'constructor' in stripped:
                    # 提取构造函数参数
                    params_match = re.search(r'constructor\s*\(([^)]*)\)', stripped)
                    if params_match:
                        params = params_match.group(1).strip()
                        # 移除依赖项相关的参数
                        if params:
                            # 简化：只保留基本参数或移除所有
                            result_lines.append(f'    constructor({params}) {{')
                        else:
                            result_lines.append('    constructor() {')
                    else:
                        result_lines.append('    constructor() {')
                else:
                    # 构造函数体中的依赖项调用，注释掉
                    result_lines.append('        // ' + stripped.lstrip() + ' // 已移除依赖项')
                continue
            
            # 保留其他代码（函数、变量等）
            result_lines.append(line)
            
            # 合约结束
            if brace_count <= 0:
                break
    
    simplified_code = '\n'.join(result_lines)
    
    # 如果简化后代码太短或没有函数，添加一个最小实现
    if len(simplified_code) < 200 or 'function' not in simplified_code:
        # 创建一个最小可编译的合约
        result_lines = []
        if spdx_line:
            result_lines.append(spdx_line)
        if pragma_line:
            result_lines.append(pragma_line)
            result_lines.append('')
        
        result_lines.append(f'contract {contract_name} {{')
        result_lines.append('    // 简化版本：已移除所有依赖项')
        result_lines.append('    // 注意：此版本仅用于基本安全扫描，可能无法检测依赖项相关问题')
        result_lines.append('}')
        
        simplified_code = '\n'.join(result_lines)
    
    return simplified_code


def scan_simplified_contract(contract_source: str, contract_name: str = "Contract") -> Optional[Dict[str, Any]]:
    """
    使用简化后的合约代码进行扫描（移除依赖项）
    
    参数:
        contract_source: 原始 Solidity 源代码
        contract_name: 合约名称
    
    返回:
        包含扫描结果的字典
    """
    try:
        # 提取主合约（移除依赖项）
        simplified_code = extract_main_contract_without_dependencies(contract_source)
        
        if not simplified_code or len(simplified_code) < 50:
            return {
                "error": "无法提取主合约",
                "message": "源代码可能不包含有效的合约定义"
            }
        
        # 尝试使用 Slither 扫描简化后的代码
        from .slither_scanner import scan_contract_with_slither_api, scan_contract_with_slither_cli, SLITHER_API_AVAILABLE, Slither
        
        # 优先使用 API
        if SLITHER_API_AVAILABLE and Slither is not None:
            try:
                result = scan_contract_with_slither_api(simplified_code, contract_name)
                if result and "error" not in result:
                    result["simplified"] = True
                    result["note"] = "⚠️  注意: 这是简化扫描（已移除依赖项），可能无法检测依赖项相关的问题"
                    return result
            except Exception:
                pass
        
        # 使用 CLI
        try:
            result = scan_contract_with_slither_cli(simplified_code, contract_name, source_files=None)
            if result and "error" not in result:
                result["simplified"] = True
                result["note"] = "⚠️  注意: 这是简化扫描（已移除依赖项），可能无法检测依赖项相关的问题"
                return result
        except Exception:
            pass
        
        return {
            "error": "简化扫描也失败",
            "message": "即使移除依赖项后仍无法扫描"
        }
        
    except Exception as e:
        return {
            "error": str(e),
            "message": f"简化扫描失败: {e}"
        }

