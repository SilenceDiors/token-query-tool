"""
CLI模块 - 命令行接口和输出格式化
"""
import sys
import json
import os
import zipfile
import tempfile
from typing import Optional, Dict, Any
from datetime import datetime

from .utils import detect_chain_type, format_supply, print_separator, print_table
from .chains import query_erc20_token, query_sui_token, query_solana_token
from .code import get_evm_contract_code, get_sui_move_code, get_solana_program_code
from .config import EVM_CHAINS


def print_code(code_info: Dict[str, Any], chain_name: str):
    """
    打印代码信息
    """
    print_separator()
    print("合约代码信息")
    print_separator()
    print()
    
    if not code_info:
        print("无法获取代码信息")
        return
    
    if not code_info.get("verified", False):
        print(f"代码状态: 未验证或无法获取")
        print(f"   原因: {code_info.get('message', '未知')}")
        
        if code_info.get('web_url'):
            print(f"   网页链接: {code_info.get('web_url')}")
            print(f"   提示: 源代码在网页上可以直接查看，无需API key")
        
        if code_info.get('note'):
            note = code_info.get('note', '')
            if 'http' not in note or not code_info.get('web_url'):
                note_lines = note.split('\n')
                for line in note_lines:
                    if line.strip():
                        print(f"      {line.strip()}")
        print()
        return
    
    print(f"代码状态: 已获取")
    print()
    
    if chain_name.lower() in EVM_CHAINS:
        # EVM链源代码
        contract_name = code_info.get("contract_name", "Unknown")
        compiler_version = code_info.get("compiler_version", "")
        optimization = code_info.get("optimization_used", "")
        format_type = code_info.get("format", "")
        
        print(f"合约名称: {contract_name}")
        if compiler_version:
            print(f"编译器版本: {compiler_version}")
        if optimization:
            print(f"优化设置: {optimization}")
        print()
        
        source_code = code_info.get("source_code")
        if format_type == "multi_file":
            print("多文件合约源代码:")
            print("-" * 80)
            combined_source = ""
            for file_path, file_content in source_code.items():
                print(f"\n文件: {file_path}")
                print("-" * 80)
                if isinstance(file_content, dict) and "content" in file_content:
                    content = file_content["content"]
                    print(content)
                    combined_source += f"// File: {file_path}\n{content}\n\n"
                else:
                    print(file_content)
                    combined_source += f"// File: {file_path}\n{file_content}\n\n"
            print()
            code_info["combined_source"] = combined_source
        else:
            print("合约源代码:")
            print("-" * 80)
            print(source_code)
            print()
            code_info["combined_source"] = source_code
    
    elif chain_name.lower() == "sui":
        package_address = code_info.get("package_address", "")
        module_count = code_info.get("module_count", 0)
        source_code = code_info.get("source_code", {})
        from_webpage = code_info.get("from_webpage", False)
        from_cli = code_info.get("from_cli", False)
        source_method = code_info.get("source_method", "rpc_normalized")
        format_type = code_info.get("format", "move_modules")
        
        print(f"Package地址: {package_address}")
        print(f"模块数量: {module_count}")
        
        if source_method == "rpc_disassembled":
            print("源代码来源: RPC disassembled（完整反编译代码，包含init函数）")
        elif from_cli:
            print("源代码来源: Sui CLI（完整源代码）")
        elif from_webpage:
            print("源代码来源: 区块浏览器（完整源代码）")
        else:
            print("源代码来源: RPC normalized信息（已转换为Move格式，不包含init函数体）")
            print("   提示: 如需查看完整的init函数，请访问区块浏览器")
        print()
        
        print("Move模块源代码:")
        print("=" * 80)
        
        if format_type == "move_source":
            for module_name, move_code in source_code.items():
                print(f"\n模块: {package_address}::{module_name}")
                print("-" * 80)
                print(move_code)
                print()
        else:
            for module_name, module_info in source_code.items():
                print(f"\n模块: {package_address}::{module_name}")
                print("=" * 80)
                
                if "fileFormatVersion" in module_info:
                    print(f"文件格式版本: {module_info['fileFormatVersion']}")
                
                if "address" in module_info:
                    print(f"模块地址: {module_info['address']}")
                
                if "structs" in module_info:
                    structs = module_info["structs"]
                    print(f"\n结构体定义 ({len(structs)} 个):")
                    for struct_name, struct_def in structs.items():
                        print(f"  - {struct_name}")
                        if "abilities" in struct_def:
                            abilities = struct_def.get("abilities", {}).get("abilities", [])
                            if abilities:
                                print(f"    能力: {', '.join(abilities)}")
                        if "fields" in struct_def:
                            print(f"    字段数: {len(struct_def['fields'])}")
                
                if "exposedFunctions" in module_info:
                    exposed = module_info["exposedFunctions"]
                    print(f"\n暴露的函数 ({len(exposed)} 个):")
                    for func_name, func_def in exposed.items():
                        visibility = func_def.get("visibility", "unknown")
                        is_entry = func_def.get("is_entry", False)
                        params = func_def.get("parameters", [])
                        return_types = func_def.get("return", [])
                        print(f"  - {func_name}")
                        print(f"    可见性: {visibility}, 入口: {is_entry}")
                        print(f"    参数: {len(params)}, 返回值: {len(return_types)}")
                
                print(f"\n完整模块信息 (JSON):")
                print("-" * 80)
                module_json = json.dumps(module_info, indent=2, ensure_ascii=False)
                print(module_json)
                print()
    
    elif chain_name.lower() == "solana":
        executable = code_info.get("executable", False)
        owner = code_info.get("owner", "")
        data_length = code_info.get("data_length", 0)
        data = code_info.get("source_code", "")
        bytecode_hex = code_info.get("bytecode_hex", "")
        bytecode_analysis = code_info.get("bytecode_analysis", {})
        note = code_info.get("note", "")
        
        print(f"可执行程序: {'是' if executable else '否'}")
        print(f"程序所有者: {owner}")
        print(f"数据长度: {data_length} 字节 (Base64)")
        if bytecode_analysis:
            print(f"字节码长度: {bytecode_analysis.get('bytecode_length', 0)} 字节")
            if 'instruction_count' in bytecode_analysis:
                print(f"可能的指令数: {bytecode_analysis['instruction_count']}")
        print()
        
        if note:
            print("重要提示:")
            note_lines = note.split('\n')
            for line in note_lines:
                if line.strip():
                    print(f"   {line.strip()}")
            print()
        
        if bytecode_analysis and bytecode_analysis.get("disassembly"):
            disassembly = bytecode_analysis["disassembly"]
            print("反汇编代码 (使用 Capstone 引擎):")
            print("-" * 80)
            display_count = min(50, len(disassembly))
            for i, insn in enumerate(disassembly[:display_count]):
                print(f"{insn['address']:>10}  {insn['bytes']:20}  {insn['mnemonic']:10}  {insn['op_str']}")
            
            if len(disassembly) > display_count:
                print(f"\n... (还有 {len(disassembly) - display_count} 条指令)")
            print()
        elif bytecode_analysis and not bytecode_analysis.get("capstone_available"):
            print("提示: 安装 Capstone 引擎可进行反汇编")
            print("   安装命令: pip install capstone")
            print()
        
        if bytecode_hex:
            print("字节码 (十六进制格式):")
            print("-" * 80)
            hex_lines = []
            for i in range(0, len(bytecode_hex), 64):
                hex_lines.append(bytecode_hex[i:i+64])
            
            display_lines = hex_lines[:20]
            for line in display_lines:
                print(line)
            
            if len(hex_lines) > 20:
                print(f"\n... (还有 {len(hex_lines) - 20} 行)")
            print()
        
        if data and len(data) < 500:
            print("原始 Base64 数据:")
            print("-" * 80)
            print(data)
            print()

def print_separator():
    """打印分隔线"""
    print("=" * 80)


def export_code_to_zip(code_info: Dict[str, Any], chain_name: str, token_address: str) -> Optional[str]:
    """
    将代码导出为 ZIP 压缩包
    
    参数:
        code_info: 代码信息字典
        chain_name: 链名称
        token_address: 代币地址
    
    返回:
        压缩包文件路径，如果失败返回 None
    """
    if not code_info or not code_info.get("verified", False):
        print("无法导出：代码未验证或不可用")
        if code_info:
            if code_info.get("message"):
                print(f"   原因: {code_info.get('message')}")
            if code_info.get("note"):
                print(f"   {code_info.get('note')}")
            if code_info.get("web_url"):
                print(f"   请访问区块浏览器查看: {code_info.get('web_url')}")
        return None
    
    if chain_name.lower() == "solana":
        print("Solana 程序代码不支持导出为压缩包")
        return None
    
    try:
        temp_dir = tempfile.mkdtemp()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_address = token_address.replace("::", "_").replace(":", "_")[:20]
        zip_filename = f"{chain_name}_{safe_address}_{timestamp}.zip"
        zip_path = os.path.join(os.getcwd(), zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if chain_name.lower() in EVM_CHAINS:
                # EVM 链：导出 Solidity 源代码
                source_code = code_info.get("source_code")
                format_type = code_info.get("format", "")
                
                if format_type == "multi_file" and isinstance(source_code, dict):
                    # 多文件合约
                    for file_path, file_content in source_code.items():
                        # 处理 content 可能是 dict 的情况
                        if isinstance(file_content, dict) and "content" in file_content:
                            content = file_content["content"]
                        else:
                            content = file_content
                        
                        # 确保文件路径安全
                        safe_path = os.path.basename(file_path)
                        if not safe_path.endswith('.sol'):
                            safe_path += '.sol'
                        
                        zipf.writestr(safe_path, content)
                else:
                    contract_name = code_info.get("contract_name", "Contract")
                    filename = f"{contract_name}.sol"
                    zipf.writestr(filename, source_code)
            
            elif chain_name.lower() == "sui":
                source_code = code_info.get("source_code", {})
                package_address = code_info.get("package_address", token_address)
                format_type = code_info.get("format", "")
                
                if format_type == "move_source" and isinstance(source_code, dict):
                    for module_name, move_code in source_code.items():
                        filename = f"{module_name}.move"
                        zipf.writestr(filename, move_code)
                else:
                    info_filename = f"{package_address}_info.json"
                    zipf.writestr(info_filename, json.dumps(code_info, indent=2, ensure_ascii=False))
        
        print(f"代码已导出到: {zip_path}")
        return zip_path
    
    except Exception as e:
        print(f"导出失败: {e}")
        return None

def print_table(data: list, headers: list = None):
    """打印表格"""
    if not data:
        return
    
    if headers:
        all_rows = [headers] + data
    else:
        all_rows = data
    
    col_widths = []
    for i in range(len(all_rows[0])):
        col_width = max(len(str(row[i])) for row in all_rows)
        col_widths.append(col_width)
    
    if headers:
        header_row = " | ".join(str(headers[i]).ljust(col_widths[i]) for i in range(len(headers)))
        print(header_row)
        print("-" * len(header_row))
    
    start_idx = 1 if headers else 0
    for row in all_rows[start_idx:]:
        data_row = " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(row)))
        print(data_row)

def get_contract_code_only(token_address: str, chain: Optional[str] = None, scan_security: bool = False) -> None:
    """
    仅获取合约代码（不查询代币信息）
    """
    print_separator()
    print("正在获取合约代码...")
    print_separator()
    print(f"合约地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        # 自动检测链类型
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    print()
    
    # 根据链类型查询代码
    code_info = None
    
    if chain_type == "sui":
        code_info = get_sui_move_code(token_address)
        chain_name = "sui"
    elif chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        code_info = get_evm_contract_code(token_address, evm_chain)
        chain_name = evm_chain
    elif chain_type == "solana":
        code_info = get_solana_program_code(token_address)
        chain_name = "solana"
    else:
        print("无法识别链类型，请手动指定")
        print()
        print("支持的格式:")
        print("   - Sui: <address>::<module>::<Type> 或对象地址 (0x...66字符)")
        print("   - EVM (ETH/BSC等): 0x... (42字符)")
        print("   - Solana: base58地址 (32-44字符)")
        return
    
    if code_info:
        print_code(code_info, chain_name)
        
        # 如果启用了安全扫描且是 EVM 链且有源代码
        if scan_security and chain_name.lower() in EVM_CHAINS:
            # 获取原始源代码（多文件时使用原始字典，单文件时使用字符串）
            original_source_code = code_info.get("source_code")
            source_code = code_info.get("combined_source") or original_source_code
            
            if source_code and (isinstance(source_code, str) and len(source_code) > 100) or (isinstance(source_code, dict) and len(source_code) > 0):
                # 使用模式匹配扫描（无需编译，无需依赖）
                print()
                print_separator()
                print("安全扫描 (模式匹配 - 无需编译)")
                print_separator()
                print()
                print("正在使用模式匹配扫描合约...")
                
                # 提取主合约代码
                if code_info.get("format") == "multi_file" and isinstance(original_source_code, dict):
                    main_file = None
                    contract_name_hint = code_info.get("contract_name", "Contract")
                    for filename, content in original_source_code.items():
                        if isinstance(content, dict) and "content" in content:
                            file_content = content["content"]
                        else:
                            file_content = content
                        
                        if contract_name_hint.lower() in filename.lower():
                            main_file = file_content
                            break
                    
                    if not main_file:
                        first_content = list(original_source_code.values())[0]
                        if isinstance(first_content, dict) and "content" in first_content:
                            main_file = first_content["content"]
                        else:
                            main_file = first_content
                    source_code = main_file
                else:
                    source_code = source_code if isinstance(source_code, str) else str(source_code)
                
                try:
                    from token_query.security import scan_with_patterns, format_pattern_scan_results
                    pattern_issues = scan_with_patterns(source_code)
                    if pattern_issues:
                        formatted_results = format_pattern_scan_results(pattern_issues)
                        print(formatted_results)
                    else:
                        print("   未发现常见安全问题")
                except Exception as e:
                    print(f"   ⚠️  模式匹配扫描失败: {e}")
                
                # 添加 GoPlus Labs 代币安全信息
                try:
                    from token_query.security import get_token_security_info, format_goplus_results
                    print()
                    print("正在获取代币安全信息 (GoPlus Labs)...")
                    token_addr = code_info.get("contract_address") or token_address
                    goplus_info, error_msg = get_token_security_info(token_addr, chain_name)
                    if goplus_info:
                        goplus_output = format_goplus_results(goplus_info)
                        print(goplus_output)
                    elif error_msg:
                        print(f"   {error_msg}")
                    else:
                        print("   无法获取 GoPlus 安全信息（可能该代币未在 GoPlus 数据库中）")
                except Exception as e:
                    pass
                print()
    else:
        print("无法获取合约代码")
    
    print_separator()
    print("查询完成")
    print_separator()

def query_token_universal(token_address: str, chain: Optional[str] = None, include_code: bool = True, scan_security: bool = False):
    """通用代币查询"""
    print_separator()
    print("正在查询代币信息...")
    print_separator()
    print(f"代币地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        # 处理别名
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        # 自动检测链类型
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    
    # 根据链类型查询
    token_info = None
    
    if chain_type == "sui":
        print("查询 Sui 代币...")
        token_info = query_sui_token(token_address)
    
    elif chain_type == "evm":
        # 如果没有指定具体链，默认以太坊
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        token_info = query_erc20_token(token_address, evm_chain)
    
    elif chain_type == "solana":
        print("查询 Solana 代币...")
        token_info = query_solana_token(token_address)
    
    else:
        print("无法识别链类型，请手动指定")
        print()
        print("支持的格式:")
        print("   - Sui: <address>::<module>::<Type> 或对象地址 (0x...66字符)")
        print("   - EVM (ETH/BSC等): 0x... (42字符)")
        print("   - Solana: base58地址 (32-44字符)")
        return
    
    print()
    
    if not token_info:
        print("无法获取代币信息")
        print("可能原因:")
        print("   - 地址格式不正确")
        print("   - 代币不存在")
        print("   - RPC节点问题")
        print("   - 网络连接问题")
        return
    
    print_separator()
    print("代币详细信息")
    print_separator()
    print()
    
    basic_info = [
        ["链", token_info.get('chain', 'N/A').upper()],
        ["名称", token_info.get('name', 'N/A')],
        ["符号", token_info.get('symbol', 'N/A')],
        ["精度", f"{token_info.get('decimals', 0)} 位小数"],
        ["地址", token_info.get('address', 'N/A')]
    ]
    
    if token_info.get('coinType') and token_info.get('coinType') != token_info.get('address'):
        basic_info.append(["代币类型", token_info.get('coinType', 'N/A')])
    
    print_table(basic_info, ["字段", "值"])
    print()
    
    # 供应量信息
    total_supply = token_info.get('totalSupply')
    decimals = token_info.get('decimals', 0)
    
    if total_supply is not None:
        formatted_supply = format_supply(total_supply, decimals)
        supply_info = [
            ["总供应量", f"{formatted_supply} {token_info.get('symbol', 'TOKEN')}"],
            ["原始值", str(total_supply)]
        ]
        print_table(supply_info, ["字段", "值"])
        print()
    else:
        # 如果无法获取总供应量，显示提示信息
        supply_info = [
            ["总供应量", "无法获取（可能是 regulated currency 或其他机制）"]
        ]
        print_table(supply_info, ["字段", "值"])
        print()
    
    # 区块浏览器链接
    chain_name = token_info.get('chain', '').lower()
    address = token_info.get('address', '')
    
    explorer_links = []
    if chain_name == "sui":
        if "::" in address:
            module_addr = address.split("::")[0]
            explorer_links.append(["Sui Explorer", f"https://suiexplorer.com/object/{module_addr}"])
            explorer_links.append(["SuiScan", f"https://suiscan.xyz/mainnet/object/{module_addr}"])
    elif chain_name == "ethereum":
        explorer_links.append(["Etherscan", f"https://etherscan.io/token/{address}"])
        explorer_links.append(["Ethplorer", f"https://ethplorer.io/address/{address}"])
    elif chain_name == "bsc":
        explorer_links.append(["BSCScan", f"https://bscscan.com/token/{address}"])
    elif chain_name == "polygon":
        explorer_links.append(["PolygonScan", f"https://polygonscan.com/token/{address}"])
    elif chain_name == "solana":
        explorer_links.append(["Solscan", f"https://solscan.io/token/{address}"])
        explorer_links.append(["Solana Explorer", f"https://explorer.solana.com/address/{address}"])
    
    if explorer_links:
        print_table(explorer_links, ["区块浏览器", "链接"])
        print()
    
    if include_code:
        print()
        print("正在查询合约代码...")
        code_info = None
        
        if chain_name == "sui":
            # 对于Sui，优先使用coinType（如果存在），否则使用address
            sui_address = token_info.get('coinType') or token_info.get('address', token_address)
            code_info = get_sui_move_code(sui_address)
        elif chain_name in EVM_CHAINS:
            code_info = get_evm_contract_code(token_info.get('address', token_address), chain_name)
        elif chain_name == "solana":
            code_info = get_solana_program_code(token_info.get('address', token_address))
        
        if code_info:
            print_code(code_info, chain_name)
            
            # 如果启用了安全扫描且是 EVM 链且有源代码
            if scan_security and chain_name.lower() in EVM_CHAINS:
                # 获取原始源代码（多文件时使用原始字典，单文件时使用字符串）
                original_source_code = code_info.get("source_code")
                source_code = code_info.get("combined_source") or original_source_code
                
                if source_code and (isinstance(source_code, str) and len(source_code) > 100) or (isinstance(source_code, dict) and len(source_code) > 0):
                    # 使用模式匹配扫描（无需编译，无需依赖）
                    print()
                    print_separator()
                    print("安全扫描 (模式匹配 - 无需编译)")
                    print_separator()
                    print()
                    print("正在使用模式匹配扫描合约...")
                    
                    # 提取主合约代码
                    if code_info.get("format") == "multi_file" and isinstance(original_source_code, dict):
                        main_file = None
                        contract_name_hint = code_info.get("contract_name", "Contract")
                        for filename, content in original_source_code.items():
                            if isinstance(content, dict) and "content" in content:
                                file_content = content["content"]
                            else:
                                file_content = content
                            
                            if contract_name_hint.lower() in filename.lower():
                                main_file = file_content
                                break
                        
                        if not main_file:
                            first_content = list(original_source_code.values())[0]
                            if isinstance(first_content, dict) and "content" in first_content:
                                main_file = first_content["content"]
                            else:
                                main_file = first_content
                        source_code = main_file
                    else:
                        source_code = source_code if isinstance(source_code, str) else str(source_code)
                    
                    try:
                        from token_query.security import scan_with_patterns, format_pattern_scan_results
                        pattern_issues = scan_with_patterns(source_code)
                        if pattern_issues:
                            formatted_results = format_pattern_scan_results(pattern_issues)
                            print(formatted_results)
                        else:
                            print("   未发现常见安全问题")
                    except Exception as e:
                        print(f"   模式匹配扫描失败: {e}")
                    
                    # 添加 GoPlus Labs 代币安全信息
                    try:
                        from token_query.security import get_token_security_info, format_goplus_results
                        print()
                        print("正在获取代币安全信息 (GoPlus Labs)...")
                        token_addr = code_info.get("contract_address") or token_address
                        goplus_info, error_msg = get_token_security_info(token_addr, chain_name)
                        if goplus_info:
                            goplus_output = format_goplus_results(goplus_info)
                            print(goplus_output)
                        elif error_msg:
                            print(f"   {error_msg}")
                        else:
                            print("   无法获取 GoPlus 安全信息（可能该代币未在 GoPlus 数据库中）")
                    except Exception as e:
                        pass
                    print()
    
    print_separator()
    print("查询完成")
    print_separator()


def query_token_info_only(token_address: str, chain: Optional[str] = None):
    """
    仅查询代币基础信息（不包含代码）
    """
    print_separator()
    print("正在查询代币基础信息...")
    print_separator()
    print(f"代币地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    print()
    
    # 根据链类型查询
    token_info = None
    
    if chain_type == "sui":
        token_info = query_sui_token(token_address)
    elif chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        token_info = query_erc20_token(token_address, evm_chain)
    elif chain_type == "solana":
        token_info = query_solana_token(token_address)
    else:
        print("无法识别链类型，请手动指定")
        return
    
    print()
    
    if not token_info:
        print("无法获取代币信息")
        return
    
    # 显示结果
    print_separator()
    print("代币详细信息（来自区块链浏览器）")
    print_separator()
    print()
    
    # 基本信息表格
    basic_info = [
        ["链", token_info.get('chain', 'N/A').upper()],
        ["名称", token_info.get('name', 'N/A')],
        ["符号", token_info.get('symbol', 'N/A')],
        ["精度", f"{token_info.get('decimals', 0)} 位小数"],
        ["地址", token_info.get('address', 'N/A')]
    ]
    
    if token_info.get('coinType') and token_info.get('coinType') != token_info.get('address'):
        basic_info.append(["代币类型", token_info.get('coinType', 'N/A')])
    
    print_table(basic_info, ["字段", "值"])
    print()
    
    # 供应量信息
    total_supply = token_info.get('totalSupply')
    decimals = token_info.get('decimals', 0)
    
    if total_supply is not None:
        formatted_supply = format_supply(total_supply, decimals)
        supply_info = [
            ["总供应量", f"{formatted_supply} {token_info.get('symbol', 'TOKEN')}"],
            ["原始值", str(total_supply)]
        ]
        print_table(supply_info, ["字段", "值"])
        print()
    else:
        # 如果无法获取总供应量，显示提示信息
        supply_info = [
            ["总供应量", "无法获取（可能是 regulated currency 或其他机制）"]
        ]
        print_table(supply_info, ["字段", "值"])
        print()
    
    # 区块浏览器链接
    chain_name = token_info.get('chain', '').lower()
    address = token_info.get('address', '')
    
    explorer_links = []
    if chain_name == "sui":
        if "::" in address:
            module_addr = address.split("::")[0]
            explorer_links.append(["Sui Explorer", f"https://suiexplorer.com/object/{module_addr}"])
            explorer_links.append(["SuiScan", f"https://suiscan.xyz/mainnet/object/{module_addr}"])
    elif chain_name == "ethereum":
        explorer_links.append(["Etherscan", f"https://etherscan.io/token/{address}"])
        explorer_links.append(["Ethplorer", f"https://ethplorer.io/address/{address}"])
    elif chain_name == "bsc":
        explorer_links.append(["BSCScan", f"https://bscscan.com/token/{address}"])
    elif chain_name == "polygon":
        explorer_links.append(["PolygonScan", f"https://polygonscan.com/token/{address}"])
    elif chain_name == "solana":
        explorer_links.append(["Solscan", f"https://solscan.io/token/{address}"])
        explorer_links.append(["Solana Explorer", f"https://explorer.solana.com/address/{address}"])
    
    if explorer_links:
        print_table(explorer_links, ["区块浏览器", "链接"])
        print()
    
    print_separator()
    print("查询完成")
    print_separator()


def generate_llm_prompt(token_address: str, chain_type: str, chain_name: str, 
                        token_info: Optional[Dict[str, Any]] = None,
                        code_info: Optional[Dict[str, Any]] = None,
                        scan_results: Optional[Dict[str, Any]] = None,
                        goplus_info: Optional[Dict[str, Any]] = None,
                        _code_info_for_snippets: Optional[Dict[str, Any]] = None) -> str:
    """
    生成LLM提示词，将所有扫描结果合并成美观的文档格式
    
    参数:
        token_address: 代币地址
        chain_type: 链类型 (evm, sui, solana)
        chain_name: 链名称
        token_info: 代币基础信息
        code_info: 代码信息
        scan_results: 安全扫描结果
        goplus_info: GoPlus Labs 安全信息
    
    返回:
        LLM提示词字符串
    """
    prompt_parts = []
    
    # 标题
    prompt_parts.append("=" * 80)
    prompt_parts.append("代币安全审计报告生成提示词")
    prompt_parts.append("=" * 80)
    prompt_parts.append("")
    prompt_parts.append("请根据以下信息生成一份专业、美观的代币安全审计报告。")
    prompt_parts.append("")
    
    # 基本信息
    prompt_parts.append("## 1. 代币基本信息")
    prompt_parts.append("-" * 80)
    prompt_parts.append(f"代币地址: {token_address}")
    prompt_parts.append(f"链类型: {chain_type.upper()}")
    prompt_parts.append(f"链名称: {chain_name}")
    prompt_parts.append("")
    
    if token_info:
        prompt_parts.append("### 代币详情:")
        prompt_parts.append(f"- 名称: {token_info.get('name', 'N/A')}")
        prompt_parts.append(f"- 符号: {token_info.get('symbol', 'N/A')}")
        prompt_parts.append(f"- 精度: {token_info.get('decimals', 0)} 位小数")
        if token_info.get('totalSupply'):
            prompt_parts.append(f"- 总供应量: {format_supply(token_info.get('totalSupply'), token_info.get('decimals', 0))} {token_info.get('symbol', 'TOKEN')}")
        if token_info.get('coinType'):
            prompt_parts.append(f"- 代币类型: {token_info.get('coinType')}")
        if token_info.get('description'):
            prompt_parts.append(f"- 描述: {token_info.get('description')}")
        prompt_parts.append("")
    
    # 代码信息
    if code_info:
        prompt_parts.append("## 2. 合约代码信息")
        prompt_parts.append("-" * 80)
        prompt_parts.append(f"代码状态: {'已验证' if code_info.get('verified') else '未验证'}")
        
        if code_info.get('verified'):
            if chain_type == "evm":
                contract_name = code_info.get('contract_name', 'N/A')
                token_name = code_info.get('token_name')
                token_symbol = code_info.get('token_symbol')
                is_dynamic_name = code_info.get('is_dynamic_name', False)
                is_dynamic_symbol = code_info.get('is_dynamic_symbol', False)
                is_proxy = code_info.get('is_proxy', False)
                impl_address = code_info.get('implementation_address')
                proxy_address = code_info.get('proxy_address')
                
                # 如果是代理合约，显示代理信息
                if is_proxy:
                    if proxy_address:
                        prompt_parts.append(f"代理合约地址: {proxy_address}")
                    if impl_address:
                        prompt_parts.append(f"实现合约地址: {impl_address}")
                
                # 优先显示从代码中提取的代币名称和符号
                if token_name:
                    name_note = "（动态参数）" if is_dynamic_name else ""
                    prompt_parts.append(f"代币名称: {token_name}{name_note}")
                elif is_dynamic_name:
                    prompt_parts.append(f"代币名称: 动态参数（需从构造函数或初始化函数传入）")
                
                if token_symbol:
                    symbol_note = "（动态参数）" if is_dynamic_symbol else ""
                    prompt_parts.append(f"代币符号: {token_symbol}{symbol_note}")
                elif is_dynamic_symbol:
                    prompt_parts.append(f"代币符号: 动态参数（需从构造函数或初始化函数传入）")
                
                prompt_parts.append(f"合约名称: {contract_name}")
                prompt_parts.append(f"编译器版本: {code_info.get('compiler_version', 'N/A')}")
                prompt_parts.append(f"优化设置: {code_info.get('optimization_used', 'N/A')}")
                prompt_parts.append(f"代码格式: {code_info.get('format', 'N/A')}")
                
                # 代码摘要（不包含完整代码，只包含关键信息）
                source_code = code_info.get("source_code")
                if isinstance(source_code, str):
                    # 提取关键信息
                    lines = source_code.split('\n')
                    prompt_parts.append(f"代码行数: {len(lines)}")
                    # 提取合约定义
                    for line in lines[:50]:
                        if 'contract' in line.lower() or 'interface' in line.lower() or 'library' in line.lower():
                            prompt_parts.append(f"关键定义: {line.strip()}")
                            break
                elif isinstance(source_code, dict):
                    prompt_parts.append(f"文件数量: {len(source_code)}")
                    prompt_parts.append("主要文件:")
                    for filename in list(source_code.keys())[:5]:
                        prompt_parts.append(f"  - {filename}")
            
            elif chain_type == "sui":
                prompt_parts.append(f"Package 地址: {code_info.get('package_address', 'N/A')}")
                prompt_parts.append(f"模块数量: {code_info.get('module_count', 0)}")
                source_code = code_info.get("source_code", {})
                if isinstance(source_code, dict):
                    prompt_parts.append("模块列表:")
                    for module_name in source_code.keys():
                        prompt_parts.append(f"  - {module_name}")
        else:
            prompt_parts.append(f"无法获取原因: {code_info.get('message', '未知')}")
        prompt_parts.append("")
    
    # 安全扫描结果
    if scan_results:
        prompt_parts.append("## 3. 安全扫描结果")
        prompt_parts.append("-" * 80)
        
        # 使用传入的code_info提取代码片段（如果没有传入，使用code_info参数）
        code_info_for_snippets = _code_info_for_snippets if _code_info_for_snippets else code_info
        
        # 提取mint分析信息（优先显示）
        mint_analysis = None
        other_issues = []
        
        if chain_type == "evm":
            # EVM 模式匹配扫描结果
            if isinstance(scan_results, list):
                # 过滤掉 LOW 级别的漏洞
                filtered_scan_results = [i for i in scan_results if i.get('severity') != 'LOW']
                
                for issue in filtered_scan_results:
                    if issue.get('title') == 'Mint功能分析':
                        mint_analysis = issue
                    else:
                        other_issues.append(issue)
                
                # 合并所有问题，mint分析放在第一个
                all_issues = []
                if mint_analysis:
                    all_issues.append(mint_analysis)
                all_issues.extend(other_issues)
                
                prompt_parts.append(f"检测到 {len(all_issues)} 个安全问题:")
                for idx, issue in enumerate(all_issues, 1):
                    prompt_parts.append(f"\n问题 #{idx}:")
                    prompt_parts.append(f"  严重程度: {issue.get('severity', 'UNKNOWN')}")
                    prompt_parts.append(f"  标题: {issue.get('title', 'N/A')}")
                    
                    # 如果是mint分析，显示详细信息（不显示描述，因为描述中已经包含了这些信息）
                    if issue.get('title') == 'Mint功能分析':
                        mint_data = issue.get('mint_analysis', {})
                        prompt_parts.append(f"  铸造形式: {mint_data.get('mint_type', '未知')}")
                        prompt_parts.append(f"  最大值限制: {mint_data.get('max_supply', '未知')}")
                        prompt_parts.append(f"  权限控制: {mint_data.get('access_control', '未知')}")
                        
                        # 如果mint在父合约中，显示继承关系代码
                        if mint_data.get('inherited_from'):
                            prompt_parts.append(f"  继承的父合约: {', '.join(mint_data.get('inherited_from', []))}")
                        prompt_parts.append(f"  位置: 第 {issue.get('line', '?')} 行")
                    else:
                        prompt_parts.append(f"  描述: {issue.get('description', 'N/A')}")
                        prompt_parts.append(f"  位置: 第 {issue.get('line', '?')} 行")
                    
                    # 提取相关代码片段（所有问题都显示代码）
                    if code_info_for_snippets and code_info_for_snippets.get("verified") and code_info_for_snippets.get("source_code"):
                        source_code = code_info_for_snippets.get("source_code")
                        if isinstance(source_code, str):
                            # 对于mint分析，优先显示mint相关代码片段
                            if issue.get('title') == 'Mint功能分析':
                                mint_data = issue.get('mint_analysis', {})
                                
                                # 如果mint在父合约中，显示继承关系代码
                                if mint_data.get('inherited_from'):
                                    lines = source_code.split('\n')
                                    for i, line in enumerate(lines, 1):
                                        if 'contract ' in line and ' is ' in line:
                                            start = max(0, i - 4)
                                            end = min(len(lines), i + 3)
                                            contract_def_code = '\n'.join(lines[start:end])
                                            prompt_parts.append("")
                                            prompt_parts.append("  相关代码（合约定义和继承关系）:")
                                            prompt_parts.append("  ```solidity")
                                            for j, code_line in enumerate(contract_def_code.split('\n'), start=start+1):
                                                prompt_parts.append(f"  {code_line}")
                                            prompt_parts.append("  ```")
                                            break
                                
                                # 显示mint函数代码
                                if mint_data.get('mint_code_snippet'):
                                    prompt_parts.append("")
                                    prompt_parts.append("  相关代码（Mint函数）:")
                                    prompt_parts.append("  ```solidity")
                                    for line in mint_data.get('mint_code_snippet').split('\n'):
                                        prompt_parts.append(f"  {line}")
                                    prompt_parts.append("  ```")
                                
                                # 显示构造函数中的mint代码
                                if mint_data.get('constructor_mint_code_snippet'):
                                    prompt_parts.append("")
                                    prompt_parts.append("  相关代码（构造函数中的Mint）:")
                                    prompt_parts.append("  ```solidity")
                                    for line in mint_data.get('constructor_mint_code_snippet').split('\n'):
                                        prompt_parts.append(f"  {line}")
                                    prompt_parts.append("  ```")
                                
                                # 显示最大供应量限制代码
                                if mint_data.get('max_supply_code_snippet'):
                                    prompt_parts.append("")
                                    prompt_parts.append("  相关代码（最大供应量限制）:")
                                    prompt_parts.append("  ```solidity")
                                    for line in mint_data.get('max_supply_code_snippet').split('\n'):
                                        prompt_parts.append(f"  {line}")
                                    prompt_parts.append("  ```")
                            else:
                                # 其他问题，显示问题行附近的代码
                                issue_line = issue.get('line', 0)
                                if issue_line and issue_line > 0:
                                    lines = source_code.split('\n')
                                    start_line = max(0, issue_line - 6)
                                    end_line = min(len(lines), issue_line + 5)
                                    code_snippet = '\n'.join(lines[start_line:end_line])
                                    if code_snippet.strip():
                                        prompt_parts.append("")
                                        prompt_parts.append(f"  相关代码 (第 {start_line+1}-{end_line} 行):")
                                        prompt_parts.append("  ```solidity")
                                        for i, line in enumerate(code_snippet.split('\n'), start=start_line+1):
                                            marker = ">>> " if i == issue_line else "    "
                                            prompt_parts.append(f"  {marker}{line}")
                                        prompt_parts.append("  ```")
                    
                    if issue.get('recommendation'):
                        prompt_parts.append(f"  建议: {issue.get('recommendation')}")
        
        elif chain_type == "sui":
            # Sui 扫描结果
            if isinstance(scan_results, dict):
                issues = scan_results.get("issues", [])
                for issue in issues:
                    if issue.get('title') == 'Mint功能分析':
                        mint_analysis = issue
                    else:
                        other_issues.append(issue)
                
                # 合并所有问题，mint分析放在第一个
                all_issues = []
                if mint_analysis:
                    all_issues.append(mint_analysis)
                all_issues.extend(other_issues)
                
                summary = scan_results.get("summary", {})
                prompt_parts.append(f"检测到 {len(all_issues)} 个安全问题:")
                prompt_parts.append(f"  - 严重 (CRITICAL): {summary.get('critical', 0)}")
                prompt_parts.append(f"  - 高危 (HIGH): {summary.get('high', 0)}")
                prompt_parts.append(f"  - 中危 (MEDIUM): {summary.get('medium', 0)}")
                # 不再显示 LOW 级别
                prompt_parts.append(f"  - 信息 (INFO): {summary.get('info', 0)}")
                prompt_parts.append("")
                
                for idx, issue in enumerate(all_issues, 1):
                    prompt_parts.append(f"\n问题 #{idx}:")
                    prompt_parts.append(f"  严重程度: {issue.get('severity', 'UNKNOWN')}")
                    prompt_parts.append(f"  标题: {issue.get('title', 'N/A')}")
                    prompt_parts.append(f"  描述: {issue.get('description', 'N/A')}")
                    prompt_parts.append(f"  位置: [{issue.get('module', 'N/A')}] 第 {issue.get('line', '?')} 行")
                    if issue.get('function') and issue.get('function') != 'N/A':
                        prompt_parts.append(f"  函数: {issue.get('function')}")
                    
                    # 如果是mint分析，显示详细信息
                    if issue.get('title') == 'Mint功能分析':
                        mint_data = issue.get('mint_analysis', {})
                        prompt_parts.append(f"  铸造形式: {mint_data.get('mint_type', '未知')}")
                        prompt_parts.append(f"  最大值限制: {mint_data.get('max_supply', '未知')}")
                        prompt_parts.append(f"  权限控制: {mint_data.get('access_control', '未知')}")
                    
                    # 提取相关代码片段（所有问题都显示代码）
                    if code_info_for_snippets and code_info_for_snippets.get("verified") and code_info_for_snippets.get("source_code"):
                        source_code_dict = code_info_for_snippets.get("source_code", {})
                        if isinstance(source_code_dict, dict):
                            module_name = issue.get('module', '')
                            if module_name and module_name in source_code_dict:
                                module_code = source_code_dict[module_name]
                                if isinstance(module_code, str):
                                    # 对于mint分析，优先显示mint相关代码片段
                                    if issue.get('title') == 'Mint功能分析':
                                        mint_data = issue.get('mint_analysis', {})
                                        
                                        # 显示mint函数代码
                                        if mint_data.get('mint_code_snippet'):
                                            prompt_parts.append("")
                                            prompt_parts.append("  相关代码（Mint函数）:")
                                            prompt_parts.append("  ```move")
                                            for line in mint_data.get('mint_code_snippet').split('\n'):
                                                prompt_parts.append(f"  {line}")
                                            prompt_parts.append("  ```")
                                        
                                        # 显示init函数中的mint代码
                                        if mint_data.get('init_mint_code_snippet'):
                                            prompt_parts.append("")
                                            prompt_parts.append("  相关代码（Init函数中的Mint）:")
                                            prompt_parts.append("  ```move")
                                            for line in mint_data.get('init_mint_code_snippet').split('\n'):
                                                prompt_parts.append(f"  {line}")
                                            prompt_parts.append("  ```")
                                        
                                        # 显示最大供应量限制代码
                                        if mint_data.get('max_supply_code_snippet'):
                                            prompt_parts.append("")
                                            prompt_parts.append("  相关代码（最大供应量限制）:")
                                            prompt_parts.append("  ```move")
                                            for line in mint_data.get('max_supply_code_snippet').split('\n'):
                                                prompt_parts.append(f"  {line}")
                                            prompt_parts.append("  ```")
                                    else:
                                        # 其他问题，显示问题行附近的代码
                                        issue_line = issue.get('line', 0)
                                        if issue_line and issue_line > 0:
                                            lines = module_code.split('\n')
                                            start_line = max(0, issue_line - 6)
                                            end_line = min(len(lines), issue_line + 5)
                                            code_snippet = '\n'.join(lines[start_line:end_line])
                                            if code_snippet.strip():
                                                prompt_parts.append("")
                                                prompt_parts.append(f"  相关代码 (第 {start_line+1}-{end_line} 行):")
                                                prompt_parts.append("  ```move")
                                                for i, line in enumerate(code_snippet.split('\n'), start=start_line+1):
                                                    marker = ">>> " if i == issue_line else "    "
                                                    prompt_parts.append(f"  {marker}{line}")
                                                prompt_parts.append("  ```")
                    
                    if issue.get('recommendation'):
                        prompt_parts.append(f"  建议: {issue.get('recommendation')}")
        prompt_parts.append("")
    
    # GoPlus Labs 安全信息
    if goplus_info:
        prompt_parts.append("## 4. GoPlus Labs 代币安全信息")
        prompt_parts.append("-" * 80)
        
        # 使用与 format_goplus_results 相同的解析逻辑
        from token_query.security.goplus_scanner import _parse_bool, _parse_float, _parse_int
        
        # 基本信息
        token_name = goplus_info.get('token_name')
        if token_name and token_name != "N/A":
            prompt_parts.append(f"代币名称: {token_name}")
        
        # 解析布尔值（处理字符串 "0"/"1" 格式）
        is_open_source = _parse_bool(goplus_info.get('is_open_source'))
        is_proxy = _parse_bool(goplus_info.get('is_proxy'))
        is_mintable = _parse_bool(goplus_info.get('is_mintable'))
        is_blacklisted = _parse_bool(goplus_info.get('is_blacklisted'))
        is_honeypot = _parse_bool(goplus_info.get('is_honeypot'))
        is_anti_whale = _parse_bool(goplus_info.get('is_anti_whale'))
        is_whitelisted = _parse_bool(goplus_info.get('is_whitelisted'))
        
        # 解析税费（处理字符串格式）
        buy_tax = _parse_float(goplus_info.get('buy_tax'))
        sell_tax = _parse_float(goplus_info.get('sell_tax'))
        
        # 解析持有者信息
        holder_count = _parse_int(goplus_info.get('holder_count'))
        total_supply = _parse_int(goplus_info.get('total_supply'))
        
        # 安全风险检测
        if is_open_source is not None:
            prompt_parts.append(f"合约开源: {'是' if is_open_source else '否'}")
        if is_proxy is not None:
            prompt_parts.append(f"代理合约: {'是' if is_proxy else '否'}")
        if is_mintable is not None:
            prompt_parts.append(f"可增发代币: {'是' if is_mintable else '否'}")
        if is_blacklisted is not None:
            prompt_parts.append(f"黑名单功能: {'是' if is_blacklisted else '否'}")
        if is_honeypot is not None:
            prompt_parts.append(f"蜜罐检测: {'是' if is_honeypot else '否'}")
        if is_anti_whale is not None:
            prompt_parts.append(f"反鲸鱼机制: {'是' if is_anti_whale else '否'}")
        if is_whitelisted is not None:
            prompt_parts.append(f"白名单功能: {'是' if is_whitelisted else '否'}")
        
        # 税费信息
        if buy_tax is not None:
            prompt_parts.append(f"买入税费: {buy_tax}%")
        if sell_tax is not None:
            prompt_parts.append(f"卖出税费: {sell_tax}%")
        
        # 供应量和持有者
        if total_supply is not None:
            prompt_parts.append(f"总供应量: {total_supply:,}")
        if holder_count is not None:
            prompt_parts.append(f"持有者数量: {holder_count:,}")
        
        # 持有者分布
        holders = goplus_info.get('holders', [])
        if holders:
            prompt_parts.append("\n持有者分布 (前5名):")
            for idx, holder in enumerate(holders[:5], 1):
                address = holder.get('address', 'N/A')
                balance = holder.get('balance', 0)
                percent = holder.get('percent', 0)
                is_contract = holder.get('is_contract', False)
                contract_tag = " (合约)" if is_contract else ""
                prompt_parts.append(f"  {idx}. {address[:10]}...{address[-8:]}{contract_tag}")
                # 格式化余额和百分比
                try:
                    balance_num = _parse_int(balance) or _parse_float(balance)
                    balance_str = f"{int(balance_num):,}" if balance_num else str(balance)
                except:
                    balance_str = str(balance)
                try:
                    percent_num = _parse_float(percent)
                    percent_str = f"{percent_num:.2f}%" if percent_num else f"{percent}%"
                except:
                    percent_str = f"{percent}%"
                prompt_parts.append(f"     持有比例: {percent_str} | 余额: {balance_str}")
        
        # 风险提示
        risk_warnings = []
        if is_honeypot:
            risk_warnings.append("检测到蜜罐风险")
        if is_mintable:
            risk_warnings.append("代币可增发，存在通胀风险")
        if is_blacklisted:
            risk_warnings.append("代币具有黑名单功能，可能被冻结")
        if buy_tax is not None and buy_tax > 5:
            risk_warnings.append(f"买入税费较高 ({buy_tax}%)")
        if sell_tax is not None and sell_tax > 5:
            risk_warnings.append(f"卖出税费较高 ({sell_tax}%)")
        if holder_count is not None and holder_count < 100:
            risk_warnings.append("持有者数量较少，可能存在集中持有风险")
        
        if risk_warnings:
            prompt_parts.append("\n风险提示:")
            for warning in risk_warnings:
                prompt_parts.append(f"  {warning}")
        
        # Mint功能分析（从GoPlus API推断，用于Solana等无法读取代码的链）
        from token_query.security.goplus_scanner import _analyze_mint_from_goplus
        goplus_mint_analysis = _analyze_mint_from_goplus(goplus_info)
        if goplus_mint_analysis:
            prompt_parts.append("\n### Mint功能分析 (基于GoPlus API数据):")
            prompt_parts.append(f"铸造形式: {goplus_mint_analysis.get('mint_type', '未知')}")
            prompt_parts.append(f"最大值限制: {goplus_mint_analysis.get('max_supply', '未知')}")
            prompt_parts.append(f"权限控制: {goplus_mint_analysis.get('access_control', '未知')}")
            prompt_parts.append("注意: 由于无法读取源代码，此分析基于GoPlus Labs API数据推断")
        
        prompt_parts.append("")
    
    # 生成报告的指令
    prompt_parts.append("## 报告生成要求")
    prompt_parts.append("-" * 80)
    prompt_parts.append("请根据以上信息生成一份专业的代币安全审计报告，要求：")
    prompt_parts.append("")
    prompt_parts.append("1. **报告结构**：")
    prompt_parts.append("   - 执行摘要（Executive Summary）")
    prompt_parts.append("   - 代币基本信息")
    prompt_parts.append("   - 代码审计结果")
    prompt_parts.append("   - 安全漏洞分析（按严重程度分类）")
    prompt_parts.append("   - GoPlus Labs 风险评估")
    prompt_parts.append("   - 综合风险评估")
    prompt_parts.append("   - 建议和改进措施")
    prompt_parts.append("")
    prompt_parts.append("2. **格式要求**：")
    prompt_parts.append("   - 使用 Markdown 格式")
    prompt_parts.append("   - 使用表格展示数据")
    prompt_parts.append("   - 使用符号增强可读性")
    prompt_parts.append("   - 重要信息使用加粗或高亮")
    prompt_parts.append("   - 代码片段使用代码块格式")
    prompt_parts.append("")
    prompt_parts.append("3. **内容要求**：")
    prompt_parts.append("   - 客观、专业、准确")
    prompt_parts.append("   - 对每个安全问题提供详细说明")
    prompt_parts.append("   - 提供具体的修复建议")
    prompt_parts.append("   - 评估整体风险等级")
    prompt_parts.append("   - 给出投资或使用建议")
    prompt_parts.append("")
    prompt_parts.append("4. **语言**：")
    prompt_parts.append("   - 使用中文")
    prompt_parts.append("   - 专业术语保持英文（如：Reentrancy、Access Control）")
    prompt_parts.append("")
    prompt_parts.append("请开始生成报告：")
    prompt_parts.append("")
    prompt_parts.append("=" * 80)
    
    return "\n".join(prompt_parts)


def query_mint_analysis(token_address: str, chain: Optional[str] = None):
    """
    只显示Mint功能分析
    """
    print_separator()
    print("正在分析Mint功能...")
    print_separator()
    print(f"代币地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    print()
    
    chain_name = evm_chain if chain_type == "evm" else chain_type
    
    # 根据链类型执行不同的分析
    if chain_type == "evm":
        print("正在获取合约代码...")
        code_info = get_evm_contract_code(token_address, chain_name)
        
        if code_info:
            if code_info.get("verified", False):
                original_source_code = code_info.get("source_code")
                source_code = code_info.get("combined_source") or original_source_code
                
                if source_code and (isinstance(source_code, str) and len(source_code) > 100) or (isinstance(source_code, dict) and len(source_code) > 0):
                    # 提取主合约代码
                    if code_info.get("format") == "multi_file" and isinstance(original_source_code, dict):
                        main_file = None
                        contract_name_hint = code_info.get("contract_name", "Contract")
                        for filename, content in original_source_code.items():
                            if isinstance(content, dict) and "content" in content:
                                file_content = content["content"]
                            else:
                                file_content = content
                            
                            if contract_name_hint.lower() in filename.lower():
                                main_file = file_content
                                break
                        
                        if not main_file:
                            first_content = list(original_source_code.values())[0]
                            if isinstance(first_content, dict) and "content" in first_content:
                                main_file = first_content["content"]
                            else:
                                main_file = first_content
                        
                        source_code = main_file if main_file else source_code
                    else:
                        source_code = source_code if isinstance(source_code, str) else str(source_code)
                    
                    try:
                        from token_query.security import scan_with_patterns
                        pattern_issues = scan_with_patterns(source_code)
                        # 只提取mint分析
                        mint_analysis = None
                        for issue in pattern_issues:
                            if issue.get('title') == 'Mint功能分析':
                                mint_analysis = issue
                                break
                        
                        if mint_analysis:
                            print()
                            print_separator()
                            print("Mint功能分析")
                            print_separator()
                            print()
                            
                            mint_data = mint_analysis.get('mint_analysis', {})
                            print(f"铸造形式: {mint_data.get('mint_type', '未知')}")
                            print(f"最大值限制: {mint_data.get('max_supply', '未知')}")
                            print(f"权限控制: {mint_data.get('access_control', '未知')}")
                            
                            # 显示检测到的权限修饰符
                            detected_modifiers = mint_data.get('detected_access_modifiers', [])
                            if detected_modifiers:
                                print(f"检测到的权限修饰符: {', '.join(set(detected_modifiers))}")
                            
                            if mint_data.get('inherited_from'):
                                print(f"继承的父合约: {', '.join(mint_data.get('inherited_from', []))}")
                            
                            # 显示建议
                            recommendation = mint_analysis.get('recommendation', '')
                            if recommendation:
                                print()
                                print("建议:")
                                print("-" * 80)
                                print(recommendation)
                            
                            print()
                            print("相关代码:")
                            print("-" * 80)
                            
                            if mint_data.get('inherited_from'):
                                # 显示合约定义和继承关系
                                lines = source_code.split('\n')
                                for i, line in enumerate(lines, 1):
                                    if 'contract ' in line and ' is ' in line:
                                        start = max(0, i - 4)
                                        end = min(len(lines), i + 3)
                                        contract_def_code = '\n'.join(lines[start:end])
                                        print("合约定义和继承关系:")
                                        print("```solidity")
                                        print(contract_def_code)
                                        print("```")
                                        break
                            
                            if mint_data.get('mint_code_snippet'):
                                print()
                                print("Mint函数:")
                                print("```solidity")
                                print(mint_data.get('mint_code_snippet'))
                                print("```")
                            
                            if mint_data.get('constructor_mint_code_snippet'):
                                print()
                                print("构造函数中的Mint:")
                                print("```solidity")
                                print(mint_data.get('constructor_mint_code_snippet'))
                                print("```")
                            
                            if mint_data.get('max_supply_code_snippet'):
                                print()
                                print("最大供应量限制:")
                                print("```solidity")
                                print(mint_data.get('max_supply_code_snippet'))
                                print("```")
                        else:
                            print("   未检测到Mint功能")
                    except Exception as e:
                        print(f"   分析失败: {e}")
                else:
                    # 代码未验证或无法获取
                    print()
                    print("无法获取合约代码")
                    if code_info.get("message"):
                        print(f"   原因: {code_info.get('message')}")
                    if code_info.get("web_url"):
                        print(f"   请访问区块浏览器查看: {code_info.get('web_url')}")
                    if code_info.get("note"):
                        print(f"   {code_info.get('note')}")
            else:
                # 代码未验证或无法获取
                print()
                print("无法获取合约代码")
                if code_info.get("message"):
                    print(f"   原因: {code_info.get('message')}")
                if code_info.get("web_url"):
                    print(f"   请访问区块浏览器查看: {code_info.get('web_url')}")
                if code_info.get("note"):
                    print(f"   {code_info.get('note')}")
        else:
            print("无法获取合约代码（可能该地址不是合约地址或网络错误）")
    
    elif chain_type == "sui":
        print("正在获取合约代码...")
        code_info = get_sui_move_code(token_address)
        
        # 先获取代币信息（包括小数位）
        token_info = None
        try:
            from token_query.chains.sui import query_sui_token
            token_info = query_sui_token(token_address)
        except Exception as e:
            print(f"   获取代币信息失败（将仅从代码分析）: {e}")
        
        if code_info and code_info.get("verified", False):
            source_code = code_info.get("source_code", {})
            package_address = code_info.get("package_address", token_address)
            
            try:
                from token_query.security import scan_sui_move_code
                
                if isinstance(source_code, dict) and code_info.get("format") == "move_source":
                    # 传递 token_info 给扫描函数，以便使用 decimals
                    scan_results = scan_sui_move_code(source_code, package_address, token_info=token_info)
                    if isinstance(scan_results, dict):
                        issues = scan_results.get("issues", [])
                        mint_analysis = None
                        for issue in issues:
                            if issue.get('title') == 'Mint功能分析':
                                mint_analysis = issue
                                break
                        
                        if mint_analysis:
                            print()
                            print_separator()
                            print("Mint功能分析")
                            print_separator()
                            print()
                            
                            mint_data = mint_analysis.get('mint_analysis', {})
                            print(f"铸造形式: {mint_data.get('mint_type', '未知')}")
                            print(f"最大值限制: {mint_data.get('max_supply', '未知')}")
                            print(f"权限控制: {mint_data.get('access_control', '未知')}")
                            
                            # 显示检测到的权限修饰符
                            detected_modifiers = mint_data.get('detected_access_modifiers', [])
                            if detected_modifiers:
                                print(f"检测到的权限修饰符: {', '.join(set(detected_modifiers))}")
                            
                            # 显示建议
                            recommendation = mint_analysis.get('recommendation', '')
                            if recommendation:
                                print()
                                print("建议:")
                                print("-" * 80)
                                print(recommendation)
                            
                            print()
                            print("相关代码:")
                            print("-" * 80)
                            
                            if mint_data.get('mint_code_snippet'):
                                print("Mint函数:")
                                print("```move")
                                print(mint_data.get('mint_code_snippet'))
                                print("```")
                            
                            if mint_data.get('init_mint_code_snippet'):
                                print()
                                print("Init函数中的Mint:")
                                print("```move")
                                print(mint_data.get('init_mint_code_snippet'))
                                print("```")
                            
                            if mint_data.get('max_supply_code_snippet'):
                                print()
                                print("最大供应量限制:")
                                print("```move")
                                print(mint_data.get('max_supply_code_snippet'))
                                print("```")
                        else:
                            # 如果代码扫描未找到 mint，尝试从 GoPlus 获取
                            print("   代码扫描未检测到Mint功能，尝试从GoPlus Labs获取...")
                            try:
                                from token_query.security import get_token_security_info
                                from token_query.security.goplus_scanner import _analyze_mint_from_goplus
                                goplus_info, error_msg = get_token_security_info(token_address, chain_name)
                                if goplus_info:
                                    mint_analysis = _analyze_mint_from_goplus(goplus_info)
                                    if mint_analysis:
                                        print()
                                        print_separator()
                                        print("Mint功能分析（基于GoPlus Labs数据）")
                                        print_separator()
                                        print()
                                        print(f"铸造形式: {mint_analysis.get('mint_type', '未知')}")
                                        print(f"最大值限制: {mint_analysis.get('max_supply', '未知')}")
                                        print(f"权限控制: {mint_analysis.get('access_control', '未知')}")
                                    else:
                                        print("   无法从GoPlus获取Mint信息")
                                elif error_msg:
                                    print(f"   {error_msg}")
                                else:
                                    print("   无法获取 GoPlus 安全信息")
                            except Exception as e2:
                                print(f"   从GoPlus获取失败: {e2}")
            except Exception as e:
                print(f"   分析失败: {e}")
        else:
            print("无法获取合约代码")
            # 如果无法获取代码，尝试从 GoPlus 获取
            print("   尝试从GoPlus Labs获取Mint信息...")
            try:
                from token_query.security import get_token_security_info
                from token_query.security.goplus_scanner import _analyze_mint_from_goplus
                goplus_info, error_msg = get_token_security_info(token_address, chain_name)
                if goplus_info:
                    mint_analysis = _analyze_mint_from_goplus(goplus_info)
                    if mint_analysis:
                        print()
                        print_separator()
                        print("Mint功能分析（基于GoPlus Labs数据）")
                        print_separator()
                        print()
                        print(f"铸造形式: {mint_analysis.get('mint_type', '未知')}")
                        print(f"最大值限制: {mint_analysis.get('max_supply', '未知')}")
                        print(f"权限控制: {mint_analysis.get('access_control', '未知')}")
                    else:
                        print("   无法从GoPlus获取Mint信息")
                elif error_msg:
                    print(f"   {error_msg}")
                else:
                    print("   无法获取 GoPlus 安全信息")
            except Exception as e2:
                print(f"   从GoPlus获取失败: {e2}")
    
    elif chain_type == "solana":
        # Solana 无法读取代码，从GoPlus获取
        try:
            from token_query.security import get_token_security_info, format_goplus_results
            print("正在获取代币安全信息 (GoPlus Labs)...")
            goplus_info, error_msg = get_token_security_info(token_address, chain_name)
            if goplus_info:
                # 从GoPlus结果中提取mint信息
                from token_query.security.goplus_scanner import _analyze_mint_from_goplus
                mint_analysis = _analyze_mint_from_goplus(goplus_info)
                if mint_analysis:
                    print()
                    print_separator()
                    print("Mint功能分析（基于GoPlus Labs数据）")
                    print_separator()
                    print()
                    # _analyze_mint_from_goplus 直接返回 mint 数据字典，不是嵌套的
                    print(f"铸造形式: {mint_analysis.get('mint_type', '未知')}")
                    print(f"最大值限制: {mint_analysis.get('max_supply', '未知')}")
                    print(f"权限控制: {mint_analysis.get('access_control', '未知')}")
                else:
                    print("   无法从GoPlus获取Mint信息")
            elif error_msg:
                print(f"   {error_msg}")
            else:
                print("   无法获取 GoPlus 安全信息")
        except Exception as e:
            print(f"   分析失败: {e}")
    
    print()
    print_separator()
    print("分析完成")
    print_separator()


def query_goplus_info(token_address: str, chain: Optional[str] = None):
    """
    只显示GoPlus Labs代币安全信息
    """
    print_separator()
    print("正在获取GoPlus Labs代币安全信息...")
    print_separator()
    print(f"代币地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    print()
    
    chain_name = evm_chain if chain_type == "evm" else chain_type
    
    # 获取GoPlus信息
    try:
        from token_query.security import get_token_security_info, format_goplus_results
        
        # 对于Sui，如果输入的是package地址，需要先查询代币信息获取coinType
        goplus_address = token_address
        if chain_type == "sui" and "::" not in token_address:
            from token_query.chains import query_sui_token
            print("检测到 package 地址，正在查找代币类型...")
            token_info = query_sui_token(token_address)
            if token_info and token_info.get("coinType"):
                goplus_address = token_info.get("coinType")
                print(f"找到 coinType: {goplus_address}")
            else:
                # 从package中查找可能的代币类型
                try:
                    import requests
                    from token_query.config import RPC_ENDPOINTS
                    rpc_url = RPC_ENDPOINTS["sui"]
                    
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
                        possible_coin_types = []
                        
                        for module_name, module_info in modules.items():
                            if "structs" in module_info:
                                structs = module_info["structs"]
                                for struct_name, struct_info in structs.items():
                                    if "Coin" in struct_name or "Token" in struct_name:
                                        coin_type = f"{token_address}::{module_name}::{struct_name}"
                                        possible_coin_types.insert(0, coin_type)
                                    else:
                                        coin_type = f"{token_address}::{module_name}::{struct_name}"
                                        possible_coin_types.append(coin_type)
                        
                        if possible_coin_types:
                            goplus_address = possible_coin_types[0]
                            print(f"使用 coinType: {goplus_address}")
                except:
                    pass
        
        # 如果是 EVM 链且未指定具体链，尝试所有 EVM 链
        try_all_evm = (chain_type == "evm" and (not chain or chain.lower() == "ethereum"))
        goplus_info, error_msg = get_token_security_info(goplus_address, chain_name, try_all_evm=try_all_evm)
        
        if goplus_info:
            goplus_output = format_goplus_results(goplus_info)
            print(goplus_output)
        elif error_msg:
            print(f"   {error_msg}")
        else:
            print("   无法获取 GoPlus 安全信息（可能该代币未在 GoPlus 数据库中）")
    except Exception as e:
        print(f"   获取失败: {e}")
    
    print()
    print_separator()
    print("查询完成")
    print_separator()


def scan_token_security(token_address: str, chain: Optional[str] = None):
    """
    安全扫描（只显示安全扫描结果，不包含mint和goplus）
    - ETH: 模式匹配扫描结果（排除mint分析）
    - SUI: Sui扫描脚本结果（排除mint分析）
    - Solana: 不支持（无法读取代码）
    """
    print_separator()
    print("正在执行安全扫描...")
    print_separator()
    print(f"代币地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    print()
    
    chain_name = evm_chain if chain_type == "evm" else chain_type
    
    # 初始化收集变量
    token_info = None
    code_info = None
    scan_results = None
    goplus_info = None
    
    # 根据链类型执行不同的扫描
    if chain_type == "evm":
        # ETH: 模式匹配扫描 + GoPlus
        print("正在获取合约代码...")
        code_info = get_evm_contract_code(token_address, chain_name)
        
        if code_info and code_info.get("verified", False):
            original_source_code = code_info.get("source_code")
            source_code = code_info.get("combined_source") or original_source_code
            
            if source_code and (isinstance(source_code, str) and len(source_code) > 100) or (isinstance(source_code, dict) and len(source_code) > 0):
                # 提取主合约代码（如果是多文件，合并主合约文件）
                if code_info.get("format") == "multi_file" and isinstance(original_source_code, dict):
                    # 多文件合约：找到主合约文件
                    main_file = None
                    contract_name_hint = code_info.get("contract_name", "Contract")
                    for filename, content in original_source_code.items():
                        if isinstance(content, dict) and "content" in content:
                            file_content = content["content"]
                        else:
                            file_content = content
                        
                        # 优先匹配合约名
                        if contract_name_hint.lower() in filename.lower():
                            main_file = file_content
                            break
                    
                    # 如果没找到，使用第一个文件
                    if not main_file:
                        first_content = list(original_source_code.values())[0]
                        if isinstance(first_content, dict) and "content" in first_content:
                            main_file = first_content["content"]
                        else:
                            main_file = first_content
                    
                    source_code = main_file if main_file else source_code
                else:
                    source_code = source_code if isinstance(source_code, str) else str(source_code)
                
                # 使用模式匹配扫描（无需编译，直接分析源代码）
                print()
                print_separator()
                print("安全扫描 (模式匹配 - 无需编译)")
                print_separator()
                print()
                print("正在使用模式匹配扫描合约...")
                
                try:
                    from token_query.security import scan_with_patterns, format_pattern_scan_results
                    pattern_issues = scan_with_patterns(source_code)
                    # 排除mint分析（mint分析有单独的--mint命令）
                    pattern_issues = [i for i in pattern_issues if i.get('title') != 'Mint功能分析']
                    scan_results = pattern_issues  # 保存扫描结果
                    if pattern_issues:
                        formatted_results = format_pattern_scan_results(pattern_issues)
                        print(formatted_results)
                    else:
                        print("   未发现常见安全问题")
                except Exception as e:
                    print(f"   ⚠️  模式匹配扫描失败: {e}")
    
    elif chain_type == "sui":
        # SUI: Sui扫描脚本 + GoPlus
        print("正在获取合约代码...")
        code_info = get_sui_move_code(token_address)
        
        if code_info and code_info.get("verified", False):
            source_code = code_info.get("source_code", {})
            package_address = code_info.get("package_address", token_address)
            
            # Sui 扫描
            try:
                from token_query.security import scan_sui_move_code, format_sui_scan_results
                
                if isinstance(source_code, dict) and code_info.get("format") == "move_source":
                    print()
                    print_separator()
                    print("Sui Move 安全扫描")
                    print_separator()
                    print()
                    
                    scan_results = scan_sui_move_code(source_code, package_address)
                    # 排除mint分析（mint分析有单独的--mint命令）
                    if isinstance(scan_results, dict):
                        issues = scan_results.get("issues", [])
                        scan_results["issues"] = [i for i in issues if i.get('title') != 'Mint功能分析']
                        # 重新计算统计
                        summary = scan_results.get("summary", {})
                        critical = [i for i in scan_results["issues"] if i.get('severity') == 'CRITICAL']
                        high = [i for i in scan_results["issues"] if i.get('severity') == 'HIGH']
                        medium = [i for i in scan_results["issues"] if i.get('severity') == 'MEDIUM']
                        low = [i for i in scan_results["issues"] if i.get('severity') == 'LOW']
                        info = [i for i in scan_results["issues"] if i.get('severity') == 'INFO']
                        summary['total_issues'] = len(scan_results["issues"])
                        summary['critical'] = len(critical)
                        summary['high'] = len(high)
                        summary['medium'] = len(medium)
                        summary['low'] = len(low)
                        summary['info'] = len(info)
                    
                    formatted_results = format_sui_scan_results(scan_results)
                    print(formatted_results)
            except Exception as e:
                print(f"Sui 扫描失败: {e}")
                scan_results = None
    
    elif chain_type == "solana":
        # Solana: 不支持（无法读取代码）
        print("   Solana 链不支持安全扫描（无法读取代码）")
        print("   请使用 --goplus 命令查看 GoPlus Labs 安全信息")
    
    print()
    print_separator()
    print("扫描完成")
    print_separator()


def export_code_package(token_address: str, chain: Optional[str] = None):
    """
    导出代码压缩包（EVM和Sui，不包括Solana）
    """
    print_separator()
    print("正在获取合约代码并生成压缩包...")
    print_separator()
    print(f"合约地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    print()
    
    # Solana 不支持导出
    if chain_type == "solana":
        print("⚠️  Solana 程序代码不支持导出为压缩包")
        return
    
    # 根据链类型查询代码
    code_info = None
    chain_name = None
    
    if chain_type == "sui":
        code_info = get_sui_move_code(token_address)
        chain_name = "sui"
    elif chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        code_info = get_evm_contract_code(token_address, evm_chain)
        chain_name = evm_chain
    else:
        print("无法识别链类型，请手动指定")
        return
    
    if code_info:
        zip_path = export_code_to_zip(code_info, chain_name, token_address)
        if zip_path:
            print()
            print_separator()
            print("导出完成")
            print_separator()
    else:
        print("无法获取合约代码")
    
    print_separator()
    print("查询完成")
    print_separator()


def generate_llm_report(token_address: str, chain: Optional[str] = None):
    """
    生成LLM提示词报告
    收集所有信息（代币信息、代码信息、安全扫描结果、GoPlus信息）并生成LLM提示词
    """
    print_separator()
    print("正在生成LLM文档提示词...")
    print_separator()
    print(f"代币地址: {token_address}")
    print()
    
    # 检测链类型
    if chain:
        chain_type = chain.lower()
        if chain_type == "eth":
            chain_type = "ethereum"
        elif chain_type == "sol":
            chain_type = "solana"
        
        if chain_type in EVM_CHAINS:
            chain_type = "evm"
        elif chain_type == "solana":
            chain_type = "solana"
        elif chain_type == "sui":
            chain_type = "sui"
    else:
        chain_type, token_address = detect_chain_type(token_address)
    
    # 显示检测结果
    if chain_type == "evm":
        evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
        if chain:
            print(f"检测到的链类型: EVM - {evm_chain} (用户指定)")
        else:
            print(f"检测到的链类型: EVM - {evm_chain} (自动检测，默认以太坊)")
    else:
        if chain:
            print(f"检测到的链类型: {chain_type.upper()} (用户指定)")
        else:
            print(f"检测到的链类型: {chain_type.upper()} (自动检测)")
    print()
    
    chain_name = evm_chain if chain_type == "evm" else chain_type
    
    # 初始化收集变量
    token_info = None
    code_info = None
    scan_results = None
    goplus_info = None
    
    # 1. 获取代币基础信息
    print("正在获取代币基础信息...")
    try:
        if chain_type == "sui":
            token_info = query_sui_token(token_address)
        elif chain_type == "evm":
            evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
            token_info = query_erc20_token(token_address, evm_chain)
        elif chain_type == "solana":
            token_info = query_solana_token(token_address)
    except Exception as e:
        print(f"   获取代币信息失败: {e}")
    
    # 2. 获取代码信息
    print("正在获取合约代码...")
    try:
        if chain_type == "sui":
            code_info = get_sui_move_code(token_address)
        elif chain_type == "evm":
            evm_chain = chain.lower() if chain and chain.lower() in EVM_CHAINS else "ethereum"
            code_info = get_evm_contract_code(token_address, evm_chain)
            if code_info:
                if code_info.get("verified"):
                    print(f"   代码获取成功: {code_info.get('format', 'unknown')} 格式")
                    if code_info.get("format") == "single_file":
                        code_len = len(code_info.get("source_code", ""))
                        print(f"   代码长度: {code_len} 字符")
                        # 如果代码太短，可能是只获取到了部分代码
                        if code_len < 1000:
                            print(f"   警告: 代码长度较短，可能只获取到部分代码")
                            # 显示前200字符预览
                            preview = code_info.get("source_code", "")[:200]
                            print(f"   代码预览: {preview}...")
                    elif code_info.get("format") == "multi_file":
                        file_count = len(code_info.get("source_code", {}))
                        print(f"   文件数量: {file_count}")
                        # 显示文件列表
                        for filename in list(code_info.get("source_code", {}).keys())[:5]:
                            print(f"     - {filename}")
                else:
                    print(f"   代码未验证: {code_info.get('message', '未知原因')}")
                    if code_info.get("web_url"):
                        print(f"   请手动查看: {code_info.get('web_url')}")
            else:
                print("   无法获取代码信息")
        elif chain_type == "solana":
            code_info = get_solana_program_code(token_address)
    except Exception as e:
        print(f"   获取代码信息失败: {e}")
        import traceback
        traceback.print_exc()
    
    # 3. 执行安全扫描
    print("正在执行安全扫描...")
    try:
        if chain_type == "evm" and code_info:
            if not code_info.get("verified", False):
                print("   代码未验证，跳过安全扫描")
            else:
                original_source_code = code_info.get("source_code")
            source_code = code_info.get("combined_source") or original_source_code
            
            if source_code and (isinstance(source_code, str) and len(source_code) > 100) or (isinstance(source_code, dict) and len(source_code) > 0):
                # 提取主合约代码
                if code_info.get("format") == "multi_file" and isinstance(original_source_code, dict):
                    main_file = None
                    contract_name_hint = code_info.get("contract_name", "Contract")
                    for filename, content in original_source_code.items():
                        if isinstance(content, dict) and "content" in content:
                            file_content = content["content"]
                        else:
                            file_content = content
                        if contract_name_hint.lower() in filename.lower():
                            main_file = file_content
                            break
                    if not main_file:
                        first_content = list(original_source_code.values())[0]
                        if isinstance(first_content, dict) and "content" in first_content:
                            main_file = first_content["content"]
                        else:
                            main_file = first_content
                    source_code = main_file if main_file else source_code
                else:
                    source_code = source_code if isinstance(source_code, str) else str(source_code)
                
                from token_query.security import scan_with_patterns
                scan_results = scan_with_patterns(source_code)
        
        elif chain_type == "sui" and code_info and code_info.get("verified", False):
            source_code = code_info.get("source_code", {})
            package_address = code_info.get("package_address", token_address)
            
            if isinstance(source_code, dict) and code_info.get("format") == "move_source":
                from token_query.security import scan_sui_move_code
                scan_results = scan_sui_move_code(source_code, package_address)
                if isinstance(scan_results, dict):
                    print(f"   扫描完成，发现 {scan_results.get('summary', {}).get('total_issues', 0)} 个问题")
            else:
                print("   代码格式不正确，跳过安全扫描")
    except Exception as e:
        print(f"   安全扫描失败: {e}")
        import traceback
        traceback.print_exc()
    
    # 4. 获取 GoPlus Labs 信息
    print("正在获取 GoPlus Labs 安全信息...")
    try:
        from token_query.security import get_token_security_info
        
        goplus_address = token_address
        if chain_type == "sui" and "::" not in token_address:
            # 对于 Sui，如果输入的是 package 地址，需要查找 coinType
            if token_info and token_info.get("coinType"):
                goplus_address = token_info.get("coinType")
            else:
                # 从 package 模块中查找
                try:
                    import requests
                    from token_query.config import RPC_ENDPOINTS
                    rpc_url = RPC_ENDPOINTS["sui"]
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
                        possible_coin_types = []
                        for module_name, module_info in modules.items():
                            if "structs" in module_info:
                                structs = module_info["structs"]
                                for struct_name, struct_info in structs.items():
                                    coin_type = f"{token_address}::{module_name}::{struct_name}"
                                    if any(keyword in struct_name for keyword in ["Coin", "Token", "COIN", "TOKEN"]):
                                        possible_coin_types.insert(0, coin_type)
                                    else:
                                        possible_coin_types.append(coin_type)
                        if possible_coin_types:
                            goplus_address = possible_coin_types[0]
                except Exception:
                    pass
        
        try_all_evm = (chain_type == "evm" and (not chain or chain.lower() == "ethereum"))
        goplus_info, error_msg = get_token_security_info(goplus_address, chain_name, try_all_evm=try_all_evm)
    except Exception as e:
        print(f"   获取 GoPlus 信息失败: {e}")
    
    print()
    print_separator()
    print("生成LLM文档提示词")
    print_separator()
    print()
    
    # 生成LLM提示词（传递code_info以便提取代码片段）
    llm_prompt = generate_llm_prompt(token_address, chain_type, chain_name, token_info, code_info, scan_results, goplus_info, code_info)
    print(llm_prompt)
    print()
    
    # 保存到文件
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_address = token_address.replace(":", "_").replace("/", "_")[:20]
        filename = f"token_report_{safe_address}_{timestamp}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(llm_prompt)
        print(f"提示词已保存到: {filename}")
        print(f"你可以将此提示词复制到 ChatGPT、Claude 或其他 LLM 工具中生成专业报告")
    except Exception as e:
        print(f"保存提示词失败: {e}")
    
    print_separator()
    print("完成")
    print_separator()


def print_usage():
    """打印使用说明"""
    print("使用方法:")
    print("  python3 main.py [选项] <代币地址> [链类型]")
    print()
    print("选项:")
    print("  --info, -i          显示代币基础信息（不包含代码）")
    print("  --code, -c          生成代币代码压缩包（EVM和Sui，不包括Solana）")
    print("  --mint, -m          显示Mint功能分析（铸造形式、最大值限制、权限控制）")
    print("  --goplus, -g         显示GoPlus Labs代币安全信息")
    print("  --scan, -s          显示安全扫描结果（排除mint和goplus）")
    print("                       - ETH: 模式匹配扫描结果")
    print("                       - SUI: Sui扫描脚本结果")
    print("                       - Solana: 不支持（无法读取代码）")
    print("  --llm, -l           生成LLM提示词（收集所有信息并生成文档提示词，用于提交给大模型生成报告）")
    print("  --chain, -C <链>    指定链类型（可选）")
    print("                       支持的链: ethereum, bsc, polygon, arbitrum, optimism, avalanche, sui, solana")
    print("                       如果不指定，EVM地址会自动尝试所有EVM链")
    print("  --help, -h          显示帮助信息")
    print()
    print("示例:")
    print("  # 显示代币基础信息（自动检测链类型）")
    print("  python3 main.py --info 0xdAC17F958D2ee523a2206206994597C13D831ec7")
    print()
    print("  # 指定链类型")
    print("  python3 main.py --info 0x... --chain bsc")
    print("  python3 main.py --scan 0x... --chain polygon")
    print()
    print("  # 生成代码压缩包")
    print("  python3 main.py --code 0xdAC17F958D2ee523a2206206994597C13D831ec7")
    print()
    print("  # 安全扫描（ETH: 模式匹配扫描 + GoPlus，自动尝试所有EVM链）")
    print("  python3 main.py --scan 0xdAC17F958D2ee523a2206206994597C13D831ec7")
    print()
    print("  # 安全扫描（SUI: Sui扫描 + GoPlus）")
    print("  python3 main.py --scan 0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb")
    print()
    print("  # 安全扫描（Solana: GoPlus）")
    print("  python3 main.py --scan <solana_address> --chain solana")
    print()
    print("  # 生成LLM提示词（收集所有信息并生成文档提示词）")
    print("  python3 main.py --llm 0xdAC17F958D2ee523a2206206994597C13D831ec7")
    print("  python3 main.py --llm 0x... --chain bsc")
    print()
    print("  # 兼容旧格式（第二个位置参数作为链类型）")
    print("  python3 main.py --info 0x... bsc")
    print("  python3 main.py --code 0x... polygon")

def main():
    """主函数"""
    print_separator()
    print("通用多链代币查询工具")
    print_separator()
    print()
    print("支持的区块链:")
    print("   - Sui")
    print("   - Ethereum (ETH)")
    print("   - BSC (Binance Smart Chain)")
    print("   - Polygon")
    print("   - Arbitrum")
    print("   - Optimism")
    print("   - Avalanche")
    print("   - Solana")
    print()
    
    # 解析命令行参数
    mode = None  # 'info', 'code', 'mint', 'goplus', 'scan', 'llm'
    token_address = None
    chain = None
    
    # 处理参数
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ['--info', '-i']:
            mode = 'info'
        elif arg in ['--code', '-c']:
            mode = 'code'
        elif arg in ['--mint', '-m']:
            mode = 'mint'
        elif arg in ['--goplus', '-g']:
            mode = 'goplus'
        elif arg in ['--scan', '-s']:
            mode = 'scan'
        elif arg in ['--llm', '-l']:
            mode = 'llm'
        elif arg in ['--chain', '-C']:
            # 指定链类型
            if i + 1 < len(args):
                chain = args[i + 1]
                i += 1  # 跳过下一个参数，因为已经被读取为 chain
            else:
                print("错误: --chain 需要指定链类型")
                print("支持的链: ethereum, bsc, polygon, arbitrum, optimism, avalanche, sui, solana")
                sys.exit(1)
        elif arg in ['--help', '-h']:
            print_usage()
            sys.exit(0)
        elif not token_address and not arg.startswith('-'):
            token_address = arg
        elif not chain and not arg.startswith('-'):
            # 兼容旧格式：第二个位置参数作为链类型
            chain = arg
        i += 1
    
    # 如果没有提供地址，显示使用说明
    if not token_address:
        print_usage()
        print()
        print("错误: 必须提供代币地址")
        print()
        print("示例:")
        print("  python3 main.py --info <地址>")
        print("  python3 main.py --code <地址>")
        print("  python3 main.py --mint <地址>")
        print("  python3 main.py --goplus <地址>")
        print("  python3 main.py --scan <地址>")
        print("  python3 main.py --llm <地址>")
        sys.exit(1)
    
    # 如果没有指定模式，默认显示帮助
    if not mode:
        print_usage()
        print()
        print("错误: 必须指定一个选项 (--info, --code, --mint, --goplus, --scan, 或 --llm)")
        sys.exit(1)
    
    print()
    
    # 根据模式执行
    if mode == 'info':
        query_token_info_only(token_address, chain)
    elif mode == 'code':
        export_code_package(token_address, chain)
    elif mode == 'mint':
        query_mint_analysis(token_address, chain)
    elif mode == 'goplus':
        query_goplus_info(token_address, chain)
    elif mode == 'scan':
        scan_token_security(token_address, chain)
    elif mode == 'llm':
        generate_llm_report(token_address, chain)

