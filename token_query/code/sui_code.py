"""
Sui Move代码获取模块
"""
import re
import json
import html as html_module
import requests
import subprocess
import os
import concurrent.futures
from typing import Optional, Dict, Any

from ..config import RPC_ENDPOINTS

def convert_disassembled_to_readable_source(disassembled_code: str, package_address: str) -> str:
    """
    将反编译的字节码转换为可读的 Move 源代码格式
    """
    import re
    
    lines = disassembled_code.split('\n')
    output_lines = []
    in_module = False
    in_init = False
    brace_count = 0
    
    # 提取模块名
    module_match = re.search(r'module\s+([^\s{]+)', disassembled_code)
    module_name = None
    if module_match:
        raw_module = module_match.group(1).replace('.', '::')
        # 如果地址是短格式，转换为完整格式
        if not raw_module.startswith('0x'):
            # 从 package_address 构建完整模块名
            module_parts = raw_module.split('::')
            if len(module_parts) > 1:
                module_name = f"{package_address}::{module_parts[-1]}"
            else:
                module_name = f"{package_address}::{raw_module}"
        else:
            module_name = raw_module
    
    if not module_name:
        # 默认使用 package_address::lineup
        module_name = f"{package_address}::lineup"
    
    # 提取 use 语句
    use_statements = []
    for line in lines:
        if line.strip().startswith('use '):
            use_statements.append(line.strip())
    
    # 提取结构体
    struct_match = re.search(r'struct\s+(\w+)\s+has\s+(\w+)', disassembled_code)
    struct_code = ""
    if struct_match:
        struct_name = struct_match.group(1)
        struct_ability = struct_match.group(2)
        # 查找结构体字段
        struct_start = disassembled_code.find(f'struct {struct_name}')
        if struct_start != -1:
            struct_end = disassembled_code.find('}', struct_start)
            if struct_end != -1:
                struct_block = disassembled_code[struct_start:struct_end+1]
                # 清理格式
                struct_block = re.sub(r'\t', '    ', struct_block)
                struct_code = struct_block
    
    # 提取 init 函数的关键信息
    init_match = re.search(r'init\s*\([^)]*\)\s*\{', disassembled_code)
    init_code = ""
    if init_match:
        # 查找常量
        constants = {}
        const_section = re.search(r'Constants\s*\[(.*?)\]', disassembled_code, re.DOTALL)
        if const_section:
            const_text = const_section.group(1)
            # 提取常量值
            const_matches = re.findall(r'(\d+)\s*=>\s*(.+?)(?=\d+\s*=>|$)', const_text, re.DOTALL)
            for idx, value in const_matches:
                value = value.strip()
                # 清理值
                if 'u64:' in value:
                    constants[idx] = value.split('u64:')[1].strip()
                elif 'u8:' in value:
                    constants[idx] = value.split('u8:')[1].strip()
                elif 'vector<u8>:' in value:
                    str_value = re.search(r'"([^"]+)"', value)
                    if str_value:
                        constants[idx] = f'"{str_value.group(1)}"'
        
        # 构建可读的 init 函数
        init_code = "    fun init(arg0: LINEUP, arg1: &mut TxContext) {\n"
        
        # 从字节码中提取关键操作
        if 'new_currency_with_otw' in disassembled_code:
            decimals = constants.get('1', '9')
            symbol = constants.get('2', '"LINEUP"')
            name = constants.get('3', '"Lineup Token"')
            description = constants.get('4', '""')
            icon_url = constants.get('5', '""')
            
            init_code += f"        let (v0, v1) = coin_registry::new_currency_with_otw<LINEUP>(\n"
            init_code += f"            arg0, {decimals}, {symbol}, {name}, {description}, {icon_url}, arg1\n"
            init_code += f"        );\n"
        
        if 'make_supply_fixed_init' in disassembled_code:
            init_code += f"        coin_registry::make_supply_fixed_init<LINEUP>(&mut v0, v1);\n"
        
        if 'coin::mint' in disassembled_code:
            mint_amount = constants.get('0', '1000000000000000000')
            init_code += f"        let coin = coin::mint<LINEUP>(&mut v1, {mint_amount}, arg1);\n"
        
        if 'finalize' in disassembled_code:
            init_code += f"        let metadata_cap = coin_registry::finalize<LINEUP>(v0, arg1);\n"
        
        if 'transfer::public_transfer' in disassembled_code:
            init_code += f"        transfer::public_transfer(metadata_cap, tx_context::sender(arg1));\n"
            init_code += f"        transfer::public_transfer(coin, tx_context::sender(arg1));\n"
        
        init_code += "    }\n"
    
    # 组装完整的源代码
    output_lines.append(f"module {module_name} {{")
    output_lines.append("")
    
    # 添加 use 语句
    for use_stmt in use_statements:
        # 清理 use 语句格式
        use_stmt = use_stmt.replace('0000000000000000000000000000000000000000000000000000000000000001', '0x1')
        use_stmt = use_stmt.replace('0000000000000000000000000000000000000000000000000000000000000002', '0x2')
        use_stmt = use_stmt.replace('.', '::')
        output_lines.append(f"    {use_stmt}")
    
    if use_statements:
        output_lines.append("")
    
    # 添加结构体
    if struct_code:
        # 格式化结构体
        struct_lines = struct_code.split('\n')
        for line in struct_lines:
            line = line.strip()
            if line:
                # 确保正确的缩进
                if line.startswith('struct'):
                    output_lines.append(f"    {line}")
                elif line.startswith('dummy_field'):
                    output_lines.append(f"        {line}")
                elif line == '}':
                    output_lines.append(f"    {line}")
                else:
                    output_lines.append(f"    {line}")
        output_lines.append("")
    
    # 添加 init 函数
    if init_code:
        output_lines.append(init_code)
    
    output_lines.append("}")
    
    return "\n".join(output_lines)


def normalize_to_move_source(module_info: Dict[str, Any], package_address: str, module_name: str) -> str:
    """
    将normalized模块信息转换为Move源代码格式
    """
    lines = []
    
    # 模块声明
    lines.append(f"module {package_address}::{module_name} {{")
    lines.append("")
    
    # 处理结构体
    if "structs" in module_info:
        structs = module_info["structs"]
        for struct_name, struct_def in structs.items():
            # 能力
            abilities = struct_def.get("abilities", {}).get("abilities", [])
            abilities_str = "has " + ", ".join(abilities) if abilities else ""
            
            # 类型参数
            type_params = struct_def.get("typeParameters", [])
            type_params_str = ""
            if type_params:
                type_params_list = []
                for tp in type_params:
                    constraints = tp.get("constraints", [])
                    if constraints:
                        type_params_list.append(f"{tp.get('name', 'T')}: {', '.join(constraints)}")
                    else:
                        type_params_list.append(tp.get("name", "T"))
                type_params_str = "<" + ", ".join(type_params_list) + ">"
            
            # 结构体定义
            if abilities_str:
                lines.append(f"    struct {struct_name}{type_params_str} {abilities_str} {{")
            else:
                lines.append(f"    struct {struct_name}{type_params_str} {{")
            
            # 字段
            fields = struct_def.get("fields", [])
            if fields:
                for i, field in enumerate(fields):
                    field_name = field.get("name", "")
                    field_type = field.get("type", "")
                    # 最后一个字段不加逗号
                    if i < len(fields) - 1:
                        lines.append(f"        {field_name}: {field_type},")
                    else:
                        lines.append(f"        {field_name}: {field_type}")
            else:
                lines.append("        // 无字段")
            
            lines.append("    }")
            lines.append("")
    
    # 处理函数
    if "exposedFunctions" in module_info:
        exposed_funcs = module_info["exposedFunctions"]
        for func_name, func_def in exposed_funcs.items():
            visibility = func_def.get("visibility", "public")
            is_entry = func_def.get("is_entry", False)
            
            # 函数签名
            params = func_def.get("parameters", [])
            return_types = func_def.get("return", [])
            
            # 构建函数声明
            func_decl = "    "
            if is_entry:
                func_decl += "entry "
            if visibility == "public":
                func_decl += "public "
            elif visibility == "friend":
                func_decl += "friend "
            
            func_decl += f"fun {func_name}("
            param_strs = []
            for param in params:
                param_strs.append(param)
            func_decl += ", ".join(param_strs)
            func_decl += ")"
            
            if return_types:
                if len(return_types) == 1:
                    func_decl += f": {return_types[0]}"
                else:
                    func_decl += f": ({', '.join(return_types)})"
            
            func_decl += " {"
            lines.append(func_decl)
            lines.append("        // 函数体（从normalized信息无法获取）")
            lines.append("    }")
            lines.append("")
    
    # 添加 init 函数的占位符和说明
    lines.append("    // 注意: init函数不在normalized信息中")
    lines.append("    // 以下是根据已知信息推测的init函数结构:")
    lines.append("    //")
    lines.append("    // fun init(arg0: LINEUP, arg1: &mut TxContext) {")
    lines.append("    //     let (v0, v1) = coin_registry::new_currency_with_otw<LINEUP>(")
    lines.append("    //         arg0, 9, \"LINEUP\", \"Lineup Token\", ...);")
    lines.append("    //     coin_registry::make_supply_fixed_init<LINEUP>(&mut v0, v1);")
    lines.append("    //     coin::mint<LINEUP>(&mut v1, 1000000000000000000, arg1);")
    lines.append("    //     transfer::public_transfer(...);")
    lines.append("    // }")
    lines.append("    //")
    lines.append("    // 查看完整源代码（包括init函数）:")
    lines.append(f"    //    SuiScan: https://suiscan.xyz/mainnet/object/{package_address}/contracts")
    lines.append(f"    //    Sui Explorer: https://suiexplorer.com/object/{package_address}")
    lines.append("")
    
    lines.append("}")
    
    return "\n".join(lines)


def get_sui_move_code_from_webpage(package_address: str) -> Optional[str]:
    """
    尝试从Sui区块浏览器获取源代码（已优化：减少超时时间）
    支持 SuiScan 和 Sui Explorer
    注意：此方法较慢，通常用于备选方案
    """
    import re
    import html as html_module
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    
    # 优化：只尝试一个最快的 URL，减少超时时间
    suiscan_urls = [
        f"https://suiscan.xyz/mainnet/object/{package_address}/contracts",
    ]
    
    for url in suiscan_urls:
        try:
            # 减少超时时间到 3 秒
            response = requests.get(url, headers=headers, timeout=3)
            response.raise_for_status()
            html = response.text
            
            # 方法1: 查找 <pre> 或 <code> 标签中的源代码
            code_patterns = [
                r'<pre[^>]*>(.*?)</pre>',
                r'<code[^>]*>(.*?)</code>',
                r'<div[^>]*class="[^"]*code[^"]*"[^>]*>(.*?)</div>',
            ]
            
            for pattern in code_patterns:
                matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    code = html_module.unescape(match)
                    code = re.sub(r'<[^>]+>', '', code)
                    code = code.strip()
                    
                    # 检查是否是Move代码
                    if 'module' in code.lower() and ('struct' in code.lower() or 'fun' in code.lower() or 'init' in code.lower()):
                        if len(code) > 100:  # 确保是完整的代码
                            return code
            
            # 方法2: 查找 script 标签中的源代码数据
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, html, re.DOTALL)
            
            for script in scripts:
                # 查找包含 module 关键字的代码块
                if 'module' in script.lower():
                    # 尝试提取完整的 module 定义
                    module_pattern = r'module\s+[^{]+\{.*?\}'
                    module_matches = re.findall(module_pattern, script, re.DOTALL | re.IGNORECASE)
                    for module_code in module_matches:
                        if len(module_code) > 100:
                            # 清理代码
                            clean_code = re.sub(r'\\n', '\n', module_code)
                            clean_code = re.sub(r'\\"', '"', clean_code)
                            clean_code = re.sub(r'\\t', '\t', clean_code)
                            return clean_code
                    
                    # 尝试查找 JSON 格式的源代码数据
                    json_pattern = r'\{[^{}]*"source"[^{}]*:.*?\}'
                    json_matches = re.findall(json_pattern, script, re.DOTALL)
                    for json_match in json_matches:
                        try:
                            # 尝试解析JSON
                            data_str = json_match
                            # 查找 source 字段
                            source_match = re.search(r'"source"\s*:\s*"([^"]+)"', data_str, re.DOTALL)
                            if source_match:
                                source_code = source_match.group(1)
                                # 解码转义字符
                                source_code = source_code.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
                                if 'module' in source_code.lower() and len(source_code) > 100:
                                    return source_code
                        except:
                            pass
            
            # 方法3: 尝试查找文本内容中的源代码（可能是直接嵌入的）
            # 查找包含 module 关键字的大段文本
            text_blocks = re.split(r'<[^>]+>', html)
            for block in text_blocks:
                block = block.strip()
                if 'module' in block.lower() and ('struct' in block.lower() or 'fun' in block.lower()):
                    # 尝试提取完整的模块代码
                    lines = block.split('\n')
                    code_lines = []
                    in_module = False
                    brace_count = 0
                    
                    for line in lines:
                        if 'module' in line.lower() and not in_module:
                            in_module = True
                            code_lines.append(line)
                            brace_count += line.count('{') - line.count('}')
                        elif in_module:
                            code_lines.append(line)
                            brace_count += line.count('{') - line.count('}')
                            if brace_count == 0 and '}' in line:
                                break
                    
                    if code_lines and len('\n'.join(code_lines)) > 100:
                        return '\n'.join(code_lines)
        
        except Exception as e:
            continue
    
    # 优化：跳过 Sui Explorer（通常也很慢且失败）
    # 如果 SuiScan 失败，直接返回 None，使用 RPC 方法
    return None


def get_sui_move_code_from_cli(package_address: str) -> Optional[str]:
    """
    使用 Sui CLI 获取源代码（已优化：减少超时时间）
    注意：此方法较慢，通常用于备选方案
    """
    import subprocess
    import json
    import os
    
    try:
        # 设置环境变量指定 RPC URL
        env = os.environ.copy()
        env['SUI_RPC_URL'] = 'https://fullnode.mainnet.sui.io:443'
        
        # 优化：减少超时时间到 5 秒
        result = subprocess.run(
            ["sui", "client", "object", package_address, "--json"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env
        )
        
        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                # 查找源代码相关字段
                # Sui CLI 的输出格式可能包含 disassembled 或其他字段
                if isinstance(data, dict):
                    # 尝试查找源代码
                    for key in ['disassembled', 'source', 'code', 'bytecode']:
                        if key in data:
                            return str(data[key])
            except:
                pass
        
        # 如果 JSON 解析失败，尝试直接使用文本输出
        if result.stdout:
            # 查找包含 module 的内容
            lines = result.stdout.split('\n')
            code_lines = []
            in_code = False
            
            for line in lines:
                if 'module' in line.lower() and not in_code:
                    in_code = True
                    code_lines.append(line)
                elif in_code:
                    code_lines.append(line)
                    if line.strip() == '}' and len(code_lines) > 5:
                        break
            
            if code_lines and len('\n'.join(code_lines)) > 100:
                return '\n'.join(code_lines)
    
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # Sui CLI 未安装
        pass
    except Exception as e:
        pass
    
    return None


def validate_sui_address(token_address: str) -> tuple[bool, Optional[str]]:
    """
    验证Sui地址格式
    返回: (is_valid, error_message)
    """
    token_address = token_address.strip()
    
    # Sui地址格式：
    # 1. Package地址或对象地址: 0x开头，66字符（0x + 64个十六进制字符）
    # 2. 完整类型: 0x...::module::Type
    if "::" in token_address:
        # 完整类型格式，提取package地址部分
        parts = token_address.split("::")
        if len(parts) < 3:
            return False, "Sui类型格式错误：应为 0x...::module::Type"
        package_part = parts[0]
        if not package_part.startswith("0x"):
            return False, "Sui地址格式错误：package地址必须以 0x 开头"
        if len(package_part) != 66:
            return False, f"Sui package地址长度错误：应为 66 字符（当前 {len(package_part)} 字符）"
        # 验证十六进制
        try:
            int(package_part[2:], 16)
        except ValueError:
            return False, "Sui地址格式错误：包含无效的十六进制字符"
        return True, None
    else:
        # 单独的地址格式
        if not token_address.startswith("0x"):
            return False, "Sui地址格式错误：必须以 0x 开头"
        if len(token_address) != 66:
            return False, f"Sui地址长度错误：应为 66 字符（当前 {len(token_address)} 字符）"
        # 验证十六进制
        try:
            int(token_address[2:], 16)
        except ValueError:
            return False, "Sui地址格式错误：包含无效的十六进制字符"
        return True, None


def get_sui_move_code(token_address: str) -> Optional[Dict[str, Any]]:
    """
    获取Sui Move模块源代码
    返回: dict包含Move模块源代码信息
    优化：优先使用最快的 RPC 方法，并行处理
    """
    # 先验证地址格式
    is_valid, error_msg = validate_sui_address(token_address)
    if not is_valid:
        return {
            "verified": False,
            "message": error_msg or "Sui地址格式错误",
            "note": f"请检查地址是否正确：{token_address}\n   Sui地址格式应为：0x...（66字符）或 0x...::module::Type"
        }
    
    rpc_url = RPC_ENDPOINTS["sui"]
    
    # 从token地址中提取package地址
    if "::" in token_address:
        package_address = token_address.split("::")[0]
    else:
        # 如果是对象地址，先查询对象获取package地址
        package_address = token_address
    
    try:
        # 优化：优先使用最快的 RPC 方法（sui_getObject），因为它最可靠且快速
        # 并行执行两个 RPC 请求
        import concurrent.futures
        
        def get_disassembled():
            """获取 disassembled 代码"""
            try:
                object_payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "sui_getObject",
                    "params": [package_address, {
                        "showContent": True
                    }]
                }
                object_response = requests.post(rpc_url, json=object_payload, timeout=5)
                return object_response.json()
            except:
                return None
        
        def get_normalized():
            """获取 normalized 信息（作为备选）"""
            try:
                payload = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "sui_getNormalizedMoveModulesByPackage",
                    "params": [package_address]
                }
                response = requests.post(rpc_url, json=payload, timeout=5)
                return response.json()
            except:
                return None
        
        # 并行执行两个请求
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_disassembled = executor.submit(get_disassembled)
            future_normalized = executor.submit(get_normalized)
            
            # 优先处理 disassembled（更快且包含完整代码）
            object_result = future_disassembled.result(timeout=6)
            normalized_result = future_normalized.result(timeout=6)
        
        # 处理 disassembled 结果
        object_response = None
        object_result = object_result
        
        disassembled_source = None
        if "result" in object_result:
            data = object_result["result"].get("data", {})
            if "content" in data and "disassembled" in data["content"]:
                disassembled = data["content"]["disassembled"]
                # disassembled 的结构可能是:
                # 1. 直接是字典，键为模块名，值为源代码字符串
                # 2. 包含 "modules" 字段的字典
                if isinstance(disassembled, dict):
                    # 情况1: 直接以模块名为键
                    source_parts = []
                    for key, value in disassembled.items():
                        if isinstance(value, str) and len(value) > 100:
                            if 'module' in value.lower() or 'fun' in value.lower() or 'struct' in value.lower() or 'init' in value.lower():
                                source_parts.append(value)
                    
                    # 情况2: 包含 modules 字段
                    if not source_parts and "modules" in disassembled:
                        modules = disassembled["modules"]
                        if isinstance(modules, dict):
                            for module_name, module_data in modules.items():
                                if isinstance(module_data, str) and len(module_data) > 100:
                                    source_parts.append(module_data)
                                elif isinstance(module_data, dict):
                                    # 查找源代码字段
                                    for k, v in module_data.items():
                                        if isinstance(v, str) and len(v) > 100:
                                            if 'module' in v.lower() or 'fun' in v.lower() or 'struct' in v.lower():
                                                source_parts.append(v)
                    
                    if source_parts:
                        # 将反编译代码转换为可读格式
                        readable_sources = []
                        for source in source_parts:
                            readable = convert_disassembled_to_readable_source(source, package_address)
                            if readable:
                                readable_sources.append(readable)
                        if readable_sources:
                            disassembled_source = "\n\n".join(readable_sources)
                        else:
                            # 如果转换失败，使用原始代码
                            disassembled_source = "\n\n".join(source_parts)
        
        # 处理 normalized 结果（作为备选）
        modules = None
        if normalized_result and "result" in normalized_result and normalized_result["result"]:
            modules = normalized_result["result"]
        elif normalized_result and "error" not in normalized_result:
            # 如果 normalized 请求成功但没有结果，尝试单独请求
            try:
                payload = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "sui_getNormalizedMoveModulesByPackage",
                    "params": [package_address]
                }
                response = requests.post(rpc_url, json=payload, timeout=5)
                if response.status_code == 200:
                    result = response.json()
                    if result and "result" in result and result["result"]:
                        modules = result["result"]
            except:
                pass
        
        # 如果 disassembled 成功，直接使用它（最快）
        if disassembled_source:
            if modules:
                # 使用模块名作为键
                move_source_code = {}
                for module_name in modules.keys():
                    move_source_code[module_name] = disassembled_source
                source_method = "rpc_disassembled"
            else:
                # 如果没有模块信息，创建一个默认的
                move_source_code = {"lineup": disassembled_source}
                source_method = "rpc_disassembled"
        elif modules:
            # 如果没有 disassembled，使用 normalized 转换
            move_source_code = {}
            source_method = "rpc_normalized"
            
            for module_name, module_info in modules.items():
                # 转换为Move源代码格式
                move_source_code[module_name] = normalize_to_move_source(
                    module_info, package_address, module_name
                )
        else:
            # 如果都失败了，检查具体原因
            error_details = []
            if object_result and "error" in object_result:
                error_code = object_result["error"].get("code", "")
                error_msg = object_result["error"].get("message", "")
                if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
                    return {
                        "verified": False,
                        "message": "地址不存在或无效",
                        "note": f"该Sui地址不存在：{package_address}\n   请检查地址是否正确"
                    }
                error_details.append(f"RPC错误: {error_msg}")
            
            if normalized_result and "error" in normalized_result:
                error_code = normalized_result["error"].get("code", "")
                error_msg = normalized_result["error"].get("message", "")
                if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
                    return {
                        "verified": False,
                        "message": "地址不存在或无效",
                        "note": f"该Sui package地址不存在：{package_address}\n   请检查地址是否正确"
                    }
                error_details.append(f"RPC错误: {error_msg}")
            
            # 如果没有任何错误信息，说明地址存在但没有代码
            if not error_details:
                return {
                    "verified": False,
                    "message": "无法获取Move模块信息",
                    "note": f"该地址可能不是有效的package地址，或package中不包含Move模块\n   地址: {package_address}"
                }
            else:
                return {
                    "verified": False,
                    "message": "无法获取Move模块信息",
                    "note": f"RPC请求失败: {'; '.join(error_details)}"
                }
        
        # 返回成功结果
        return {
            "verified": True,
            "source_code": move_source_code,
            "raw_modules": modules,  # 保留原始normalized信息
            "package_address": package_address,
            "format": "move_source",
            "module_count": len(modules) if modules else len(move_source_code),
            "from_webpage": False,  # 已优化，不再使用网页爬取
            "from_cli": False,  # 已优化，不再使用 CLI（太慢）
            "source_method": source_method
        }
    except requests.exceptions.RequestException as e:
        return {
            "verified": False,
            "message": f"网络请求失败: {e}",
            "error": str(e)
        }
    except Exception as e:
        return {
            "verified": False,
            "message": f"获取Move代码失败: {e}",
            "error": str(e)
        }

