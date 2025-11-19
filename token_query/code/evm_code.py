"""
EVM链合约代码获取模块
"""
import json
import re
import html
import requests
from typing import Optional, Dict, Any

from ..config import EVM_CHAINS


def validate_evm_address(token_address: str, chain: str = "ethereum") -> tuple[bool, Optional[str]]:
    """
    验证EVM地址格式和是否存在合约代码
    返回: (is_valid, error_message)
    """
    try:
        from web3 import Web3
        from ..config import RPC_ENDPOINTS
        
        # 验证地址格式
        if not token_address.startswith("0x"):
            return False, "地址格式错误：必须以 0x 开头"
        
        # EVM链地址通常是42字符（0x + 40个十六进制字符）
        # 但有些链可能有不同的长度，所以只检查最小长度
        if len(token_address) < 3:
            return False, f"地址格式错误：长度过短（当前 {len(token_address)} 字符）"
        
        # 验证是否为有效的十六进制
        try:
            # 去掉0x前缀后验证
            hex_part = token_address[2:]
            int(hex_part, 16)
        except ValueError:
            return False, "地址格式错误：包含无效的十六进制字符"
        
        # 对于标准EVM地址，检查长度是否合理
        # 标准EVM地址：0x + 40个十六进制字符 = 42字符
        # 但允许一些灵活性（比如某些链可能有不同的地址格式）
        hex_length = len(token_address) - 2  # 去掉0x前缀
        if hex_length != 40:
            # 不是标准的40字符，但可能是有效的（某些特殊链）
            # 先尝试通过RPC验证，如果RPC失败则允许继续尝试网页爬取
            pass
        
        # 检查地址是否存在合约代码
        try:
            rpc_url = RPC_ENDPOINTS.get(chain, RPC_ENDPOINTS["ethereum"])
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            
            # 尝试转换为checksum地址（如果地址格式正确）
            try:
                checksum_address = Web3.to_checksum_address(token_address)
            except ValueError:
                # 地址格式可能不正确（比如长度不对），但继续尝试
                checksum_address = token_address
            
            code = w3.eth.get_code(checksum_address)
            
            if not code or len(code.hex()) <= 2:
                return False, "该地址不是合约地址（未部署合约或为空账户）"
            
            return True, None
        except ValueError as e:
            # 地址格式错误（比如长度不对，无法转换为checksum）
            if "Invalid address" in str(e) or "checksum" in str(e).lower():
                return False, f"地址格式错误：{str(e)}"
            # 其他错误，继续尝试网页爬取
            return True, None
        except Exception as e:
            # RPC调用失败，但地址格式正确，继续尝试网页爬取
            return True, None
    except ImportError:
        # web3未安装，跳过验证
        return True, None
    except Exception:
        # 其他错误，跳过验证
        return True, None


def get_evm_contract_code_from_webpage(token_address: str, chain: str = "ethereum") -> Optional[Dict[str, Any]]:
    """
    从网页直接爬取合约源代码（不需要API key）
    """
    explorer_urls = {
        "ethereum": f"https://etherscan.io/address/{token_address}#code",
        "bsc": f"https://bscscan.com/address/{token_address}#code",
        "polygon": f"https://polygonscan.com/address/{token_address}#code",
        "arbitrum": f"https://arbiscan.io/address/{token_address}#code",
        "optimism": f"https://optimistic.etherscan.io/address/{token_address}#code",
        "avalanche": f"https://snowtrace.io/address/{token_address}#code",
    }
    
    if chain not in explorer_urls:
        return None
    
    # 先验证地址
    is_valid, error_msg = validate_evm_address(token_address, chain)
    if not is_valid:
        return {
            "verified": False,
            "message": error_msg or "地址验证失败",
            "web_url": explorer_urls[chain],
            "note": f"请检查地址是否正确：{token_address}"
        }
    
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        
        print(f"   正在从网页获取源代码: {explorer_urls[chain]}")
        response = requests.get(explorer_urls[chain], headers=headers, timeout=15)
        response.raise_for_status()
        html_content = response.text
        
        source_files = {}
        contract_name = None
        compiler_version = None
        optimization_used = None
        source_code = None
        
        # 提取合约信息（先提取，因为可能用于文件名）
        name_match = re.search(r'Contract Name[^<]*<[^>]*>([^<]+)</', html_content, re.IGNORECASE)
        if name_match:
            contract_name = name_match.group(1).strip()
        
        compiler_match = re.search(r'Compiler Version[^<]*<[^>]*>([^<]+)</', html_content, re.IGNORECASE)
        if compiler_match:
            compiler_version = compiler_match.group(1).strip()
        
        opt_match = re.search(r'Optimization Enabled[^<]*<[^>]*>([^<]+)</', html_content, re.IGNORECASE)
        if opt_match:
            optimization_used = opt_match.group(1).strip()
        
        # 方法1: 查找 js-sourcecopyarea 类的 pre 标签（最可靠）
        js_source_pattern = r'<pre[^>]*class=["\'][^"\']*js-sourcecopyarea[^"\']*["\'][^>]*>(.*?)</pre>'
        js_source_matches = re.findall(js_source_pattern, html_content, re.DOTALL | re.IGNORECASE)
        
        if js_source_matches:
            # 提取文件名（格式：File 1 of 7 : SEEK.sol）
            file_name_pattern = r'File \d+ of \d+ : ([^<\n]+)'
            file_name_matches = re.findall(file_name_pattern, html_content, re.IGNORECASE)
            
            for idx, match in enumerate(js_source_matches):
                # 先处理 HTML 实体，但要保护代码中的 < 和 > 符号
                # 将 HTML 实体转换为临时标记，避免被后续的标签删除误删
                temp_code = match
                # 替换常见的 HTML 实体
                temp_code = temp_code.replace('&lt;', '___LT___')
                temp_code = temp_code.replace('&gt;', '___GT___')
                temp_code = temp_code.replace('&amp;', '&')
                temp_code = html.unescape(temp_code)
                
                # 移除所有HTML标签
                clean_code = re.sub(r'<[^>]+>', '', temp_code)
                
                # 恢复代码中的 < 和 > 符号
                clean_code = clean_code.replace('___LT___', '<')
                clean_code = clean_code.replace('___GT___', '>')
                
                # 保留原始格式，只清理行尾空白
                lines = clean_code.split('\n')
                cleaned_lines = [line.rstrip() for line in lines]
                clean_code = '\n'.join(cleaned_lines).strip()
                
                # 验证是否是有效的 Solidity 代码
                if clean_code and len(clean_code) > 100 and ('pragma solidity' in clean_code.lower() or 'contract ' in clean_code.lower() or 'library ' in clean_code.lower() or 'import ' in clean_code.lower()):
                    # 确定文件名
                    if idx < len(file_name_matches):
                        file_name = file_name_matches[idx].strip()
                    else:
                        # 尝试从代码中提取合约名
                        contract_match = re.search(r'(?:contract|library|interface)\s+(\w+)', clean_code, re.IGNORECASE)
                        if contract_match:
                            file_name = f"{contract_match.group(1)}.sol"
                        else:
                            file_name = f"File{idx+1}.sol"
                    
                    # 过滤掉组件类文件（OpenZeppelin、LayerZero 等）
                    # 只保留主合约代码
                    is_component = False
                    file_name_lower = file_name.lower()
                    code_lower = clean_code.lower()
                    
                    # 检查是否是组件类文件
                    component_keywords = [
                        'openzeppelin', 'oz/', '@openzeppelin',
                        'layerzero', 'layerzerolabs', '@layerzerolabs',
                        'chainlink', '@chainlink',
                        'uniswap', '@uniswap',
                        'aave', '@aave',
                        'compound', '@compound',
                        'safe', '@safe',
                        'erc20.sol', 'erc721.sol', 'erc1155.sol',  # 标准库文件
                        'ownable.sol', 'context.sol', 'reentrancyguard.sol',  # 常见组件
                        'interfaces/', 'utils/', 'libraries/',  # 组件目录
                    ]
                    
                    # 检查文件名和代码内容
                    for keyword in component_keywords:
                        if keyword in file_name_lower or keyword in code_lower[:500]:  # 只检查前500字符
                            is_component = True
                            break
                    
                    # 检查是否是 import 语句为主的文件（通常是组件）
                    # 但如果文件包含 contract 定义，即使有 import 也保留（这是主合约）
                    has_contract = 'contract ' in code_lower[:2000]  # 检查前2000字符
                    if has_contract:
                        # 有 contract 定义，即使有组件 import 也保留（这是主合约文件）
                        is_component = False
                    else:
                        # 没有 contract 定义，检查是否是纯组件文件
                        import_lines = [line for line in clean_code.split('\n')[:20] if 'import' in line.lower()]
                        if len(import_lines) > 5:
                            is_component = True
                        # 如果代码太短（只有import语句），也标记为组件
                        if len(clean_code) < 500 and len(import_lines) > 0:
                            is_component = True
                    
                    # 只保留主合约文件
                    if not is_component:
                        source_files[file_name] = clean_code
        
        # 方法2: 如果方法1失败，尝试查找所有包含 editor 类的 pre 标签
        if not source_files:
            editor_pattern = r'<pre[^>]*class=["\'][^"\']*editor[^"\']*["\'][^>]*id=["\']editor\d*["\'][^>]*>(.*?)</pre>'
            editor_matches = re.findall(editor_pattern, html_content, re.DOTALL | re.IGNORECASE)
            
            for idx, match in enumerate(editor_matches):
                clean_code = html.unescape(match)
                clean_code = re.sub(r'<[^>]+>', '', clean_code)
                # 保留原始格式
                lines = clean_code.split('\n')
                cleaned_lines = [line.rstrip() for line in lines]
                clean_code = '\n'.join(cleaned_lines).strip()
                
                if clean_code and len(clean_code) > 100 and ('pragma solidity' in clean_code.lower() or 'contract ' in clean_code.lower() or 'library ' in clean_code.lower()):
                    # 过滤组件类文件
                    code_lower = clean_code.lower()
                    is_component = any(keyword in code_lower[:500] for keyword in [
                        'openzeppelin', 'layerzero', 'chainlink', 'uniswap', 'aave', 'compound'
                    ])
                    
                    if not is_component:
                        contract_match = re.search(r'(?:contract|library|interface)\s+(\w+)', clean_code, re.IGNORECASE)
                        if contract_match:
                            file_name = f"{contract_match.group(1)}.sol"
                        else:
                            file_name = f"File{idx+1}.sol"
                        source_files[file_name] = clean_code
        
        # 方法3: 如果还是失败，尝试查找所有 pre 标签，并筛选出包含 Solidity 代码的
        if not source_files:
            all_pre_pattern = r'<pre[^>]*>(.*?)</pre>'
            all_pre_matches = re.findall(all_pre_pattern, html_content, re.DOTALL | re.IGNORECASE)
            
            for idx, match in enumerate(all_pre_matches):
                clean_code = html.unescape(match)
                clean_code = re.sub(r'<[^>]+>', '', clean_code)
                clean_code = clean_code.strip()
                
                # 更严格的验证：必须包含 pragma solidity 且长度足够
                if clean_code and len(clean_code) > 500 and 'pragma solidity' in clean_code.lower():
                    # 过滤组件类文件
                    code_lower = clean_code.lower()
                    is_component = any(keyword in code_lower[:500] for keyword in [
                        'openzeppelin', 'layerzero', 'chainlink', 'uniswap', 'aave', 'compound'
                    ])
                    
                    if not is_component:
                        # 检查是否以 } 结尾（完整的合约）
                        if clean_code.rstrip().endswith('}'):
                            contract_match = re.search(r'(?:contract|library|interface)\s+(\w+)', clean_code, re.IGNORECASE)
                            if contract_match:
                                file_name = f"{contract_match.group(1)}.sol"
                            else:
                                file_name = f"Contract.sol"
                            source_files[file_name] = clean_code
                            break  # 找到第一个完整的就停止
        
        # 处理结果：只保留主合约，合并所有主合约文件
        if source_files:
            # 如果过滤后还有多个文件，找到主合约文件（通常是合约名匹配的文件）
            main_contract_code = None
            if contract_name:
                # 优先查找与合约名匹配的文件
                for file_name, code in source_files.items():
                    if contract_name.lower() in file_name.lower():
                        main_contract_code = code
                        break
            
            # 如果没找到，使用第一个文件
            if not main_contract_code:
                main_contract_code = list(source_files.values())[0]
            
            # 如果只有一个文件，直接使用
            if len(source_files) == 1:
                source_code = main_contract_code
            else:
                # 多个文件时，合并主合约相关文件（排除组件）
                # 找到主合约文件，然后合并它直接引用的其他主合约文件
                source_code = main_contract_code
                
                # 尝试从主合约的 import 中找到其他主合约文件
                import_lines = [line for line in source_code.split('\n') if 'import' in line.lower()]
                for import_line in import_lines:
                    # 提取 import 路径
                    import_match = re.search(r'import\s+["\']([^"\']+)["\']', import_line)
                    if import_match:
                        import_path = import_match.group(1)
                        # 检查是否是主合约文件（不是组件）
                        if not any(comp in import_path.lower() for comp in ['openzeppelin', 'layerzero', 'chainlink', '@']):
                            # 尝试找到对应的文件
                            for file_name, code in source_files.items():
                                if import_path.split('/')[-1].replace('.sol', '') in file_name.lower():
                                    # 合并这个文件（简单追加）
                                    source_code += "\n\n// === Merged from " + file_name + " ===\n"
                                    source_code += code
                                    break
            
            # 检查代码是否完整（必须包含 contract 定义）
            if source_code and len(source_code) > 100:
                # 检查是否只有 import 语句，没有实际的合约代码
                code_lower = source_code.lower()
                has_contract_def = 'contract ' in code_lower or 'library ' in code_lower or 'interface ' in code_lower
                import_count = len([line for line in source_code.split('\n') if 'import' in line.lower()])
                
                # 如果代码太短且只有 import 语句，说明可能只获取到了部分代码
                if len(source_code) < 1000 and not has_contract_def and import_count > 0:
                    return {
                        "verified": False,
                        "message": "代码可能通过JavaScript动态加载，无法直接爬取完整代码",
                        "web_url": explorer_urls[chain],
                        "note": f"源代码在网页上可以直接查看（无需API key）\n   请访问: {explorer_urls[chain]}\n   或使用浏览器开发者工具查看源代码",
                        "partial_code": source_code  # 保留部分代码供参考
                    }
            
            if source_code and len(source_code) > 100:
                # 检查是否是 JSON 格式（多文件合约的 JSON 格式）
                try:
                    if source_code.startswith("{{"):
                        source_code = source_code[1:-1]
                    if source_code.startswith("{"):
                        source_data = json.loads(source_code)
                        if "sources" in source_data:
                            # 过滤 sources 中的组件文件
                            filtered_sources = {}
                            for key, value in source_data["sources"].items():
                                if not any(comp in key.lower() for comp in ['openzeppelin', 'layerzero', 'chainlink', '@']):
                                    filtered_sources[key] = value
                            
                            if filtered_sources:
                                return {
                                    "verified": True,
                                    "source_code": filtered_sources,
                                    "contract_name": contract_name or "Unknown",
                                    "compiler_version": compiler_version or "",
                                    "optimization_used": optimization_used or "",
                                    "format": "multi_file",
                                    "method": "web_scraping"
                                }
                except (json.JSONDecodeError, ValueError):
                    pass
                
                # 从代码中提取代币名称和符号（如果HTML中没有提取到）
                token_name = None
                token_symbol = None
                is_dynamic_name = False
                is_dynamic_symbol = False
                
                if not contract_name or contract_name == "Unknown":
                    # 方法1: 尝试从代码中提取硬编码的 _name 和 _symbol
                    name_match = re.search(r"_name\s*=\s*['\"]([^'\"]+)['\"]", source_code, re.IGNORECASE)
                    if name_match:
                        token_name = name_match.group(1).strip()
                    
                    symbol_match = re.search(r"_symbol\s*=\s*['\"]([^'\"]+)['\"]", source_code, re.IGNORECASE)
                    if symbol_match:
                        token_symbol = symbol_match.group(1).strip()
                    
                    # 方法2: 检查构造函数或初始化函数中的动态参数
                    # 查找构造函数中的 name 和 symbol 参数
                    constructor_pattern = r'constructor\s*\([^)]*\)'
                    constructor_match = re.search(constructor_pattern, source_code, re.IGNORECASE | re.DOTALL)
                    if constructor_match:
                        constructor_code = constructor_match.group(0)
                        # 检查是否有 name 和 symbol 参数
                        if re.search(r'(?:string\s+memory\s+)?_?name', constructor_code, re.IGNORECASE):
                            is_dynamic_name = True
                        if re.search(r'(?:string\s+memory\s+)?_?symbol', constructor_code, re.IGNORECASE):
                            is_dynamic_symbol = True
                        
                        # 尝试从构造函数调用中提取值
                        # 查找 _name = _name 或 name = name 这样的赋值
                        name_assign = re.search(r'_name\s*=\s*([^;]+);', constructor_code, re.IGNORECASE)
                        if name_assign and not token_name:
                            param_value = name_assign.group(1).strip()
                            # 如果是字符串字面量
                            str_match = re.search(r'["\']([^"\']+)["\']', param_value)
                            if str_match:
                                token_name = str_match.group(1).strip()
                                is_dynamic_name = False
                            else:
                                is_dynamic_name = True
                        
                        symbol_assign = re.search(r'_symbol\s*=\s*([^;]+);', constructor_code, re.IGNORECASE)
                        if symbol_assign and not token_symbol:
                            param_value = symbol_assign.group(1).strip()
                            str_match = re.search(r'["\']([^"\']+)["\']', param_value)
                            if str_match:
                                token_symbol = str_match.group(1).strip()
                                is_dynamic_symbol = False
                            else:
                                is_dynamic_symbol = True
                    
                    # 方法3: 检查初始化函数（用于可升级合约）
                    init_pattern = r'(?:function\s+initialize|function\s+init)\s*\([^)]*\)'
                    init_match = re.search(init_pattern, source_code, re.IGNORECASE | re.DOTALL)
                    if init_match:
                        init_code = init_match.group(0)
                        if re.search(r'(?:string\s+memory\s+)?_?name', init_code, re.IGNORECASE):
                            is_dynamic_name = True
                        if re.search(r'(?:string\s+memory\s+)?_?symbol', init_code, re.IGNORECASE):
                            is_dynamic_symbol = True
                    
                    # 如果找到了名称或符号，使用它们作为合约名
                    if token_name:
                        contract_name = token_name
                    elif token_symbol:
                        contract_name = token_symbol
                
                return {
                    "verified": True,
                    "source_code": source_code,
                    "contract_name": contract_name or "Unknown",
                    "token_name": token_name,
                    "token_symbol": token_symbol,
                    "is_dynamic_name": is_dynamic_name,
                    "is_dynamic_symbol": is_dynamic_symbol,
                    "compiler_version": compiler_version or "",
                    "optimization_used": optimization_used or "",
                    "format": "single_file",
                    "method": "web_scraping"
                }
        else:
            # 检查网页内容，判断具体原因
            # 检查是否显示"Contract"标签页（说明是合约地址）
            has_contract_tab = "Contract" in html_content or "contract" in html_content.lower()
            
            # 检查是否显示"未验证"或"未开源"相关提示
            unverified_patterns = [
                r"not.*verified",
                r"unverified",
                r"source.*code.*not.*available",
                r"未验证",
                r"未开源",
                r"contract.*source.*code.*not.*available"
            ]
            is_unverified = any(re.search(pattern, html_content, re.IGNORECASE) for pattern in unverified_patterns)
            
            # 检查是否显示"地址不存在"或"无效地址"
            invalid_patterns = [
                r"invalid.*address",
                r"address.*not.*found",
                r"does.*not.*exist",
                r"无效地址",
                r"地址不存在"
            ]
            is_invalid = any(re.search(pattern, html_content, re.IGNORECASE) for pattern in invalid_patterns)
            
            if is_invalid:
                return {
                    "verified": False,
                    "message": "地址不存在或无效",
                    "web_url": explorer_urls[chain],
                    "note": f"请检查地址是否正确：{token_address}"
                }
            elif is_unverified:
                return {
                    "verified": False,
                    "message": "合约源代码未验证",
                    "web_url": explorer_urls[chain],
                    "note": f"该合约已部署但源代码未在区块浏览器上验证\n   请访问: {explorer_urls[chain]}\n   或联系合约部署者验证源代码"
                }
            elif has_contract_tab:
                return {
                    "verified": False,
                    "message": "源代码通过JavaScript动态加载，无法直接爬取",
                    "web_url": explorer_urls[chain],
                    "note": f"源代码在网页上可以直接查看（无需API key）\n   请访问: {explorer_urls[chain]}\n   或使用浏览器开发者工具查看源代码"
                }
            else:
                return {
                    "verified": False,
                    "message": "无法获取合约源代码",
                    "web_url": explorer_urls[chain],
                    "note": f"请访问区块浏览器查看: {explorer_urls[chain]}"
                }
            
    except requests.exceptions.RequestException as e:
        return {
            "verified": False,
            "message": f"网络请求失败: {e}",
            "web_url": explorer_urls.get(chain, ""),
            "error": str(e)
        }
    except Exception as e:
        return {
            "verified": False,
            "message": f"解析网页失败: {e}",
            "web_url": explorer_urls.get(chain, ""),
            "error": str(e)
        }


def get_implementation_address(token_address: str, chain: str = "ethereum") -> Optional[str]:
    """
    获取代理合约的实现合约地址
    支持 ERC1967Proxy 和 EIP-1967 标准
    """
    try:
        from web3 import Web3
        from ..config import RPC_ENDPOINTS
        
        rpc_url = RPC_ENDPOINTS.get(chain, RPC_ENDPOINTS["ethereum"])
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # ERC1967 实现地址存储槽
        # keccak256("eip1967.proxy.implementation") - 1
        IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        
        try:
            storage_value = w3.eth.get_storage_at(Web3.to_checksum_address(token_address), IMPLEMENTATION_SLOT)
            # 提取地址（最后20字节）
            impl_address = '0x' + storage_value.hex()[-40:]
            
            # 验证地址是否有效（不是全0）
            if impl_address != '0x0000000000000000000000000000000000000000':
                return Web3.to_checksum_address(impl_address)
        except:
            pass
        
        # 尝试其他常见的代理存储槽
        # EIP-1967 的另一种格式
        try:
            ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
            storage_value = w3.eth.get_storage_at(Web3.to_checksum_address(token_address), ADMIN_SLOT)
            # 如果管理员槽有值，可能是代理合约，但实现地址在另一个槽
        except:
            pass
        
        return None
    except:
        return None


def get_evm_contract_code(token_address: str, chain: str = "ethereum", api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    获取EVM链合约源代码（直接从网页爬取，不需要API key）
    支持代理合约：自动检测并获取实现合约代码
    返回: dict包含源代码信息，如果无法获取则返回None
    """
    if chain not in EVM_CHAINS:
        return None
    
    # 先尝试从存储槽检测是否是代理合约（最可靠的方法）
    impl_address = get_implementation_address(token_address, chain)
    is_proxy_by_storage = impl_address is not None
    
    # 获取代码
    code_info = get_evm_contract_code_from_webpage(token_address, chain)
    
    # 检查是否是代理合约
    is_proxy = is_proxy_by_storage
    if code_info:
        contract_name = code_info.get("contract_name", "").lower()
        # 检查合约名称是否包含代理关键词
        proxy_keywords = ["proxy", "erc1967proxy", "transparentupgradeableproxy", "uupsupgradeable"]
        if not is_proxy:
            is_proxy = any(keyword in contract_name for keyword in proxy_keywords)
        
        # 如果代码很短或没有实际代码，也可能是代理合约
        source_code = code_info.get("source_code")
        if not is_proxy and source_code:
            if isinstance(source_code, str):
                # 检查代码中是否有代理相关的关键词
                code_lower = source_code.lower()
                if "delegatecall" in code_lower and ("implementation" in code_lower or "proxy" in code_lower):
                    is_proxy = True
            elif isinstance(source_code, dict):
                # 多文件合约，检查主文件
                for file_content in source_code.values():
                    if isinstance(file_content, dict) and "content" in file_content:
                        content = file_content["content"]
                    else:
                        content = file_content
                    if isinstance(content, str) and ("delegatecall" in content.lower() and "implementation" in content.lower()):
                        is_proxy = True
                        break
        
        # 如果是代理合约，尝试获取实现合约地址和代码
        if is_proxy:
            if not impl_address:
                impl_address = get_implementation_address(token_address, chain)
            
            if impl_address:
                print(f"   检测到代理合约")
                print(f"   找到实现合约地址: {impl_address}")
                print(f"   正在获取实现合约代码...")
                impl_code_info = get_evm_contract_code_from_webpage(impl_address, chain)
                if impl_code_info and impl_code_info.get("verified", False):
                    # 合并信息，标记为代理合约
                    impl_code_info["is_proxy"] = True
                    impl_code_info["proxy_address"] = token_address
                    impl_code_info["implementation_address"] = impl_address
                    return impl_code_info
                else:
                    # 实现合约未验证，但返回代理信息
                    if code_info:
                        code_info["is_proxy"] = True
                        code_info["implementation_address"] = impl_address
                        code_info["note"] = f"这是代理合约，实现合约地址: {impl_address}\n   实现合约代码可能未验证，请访问区块浏览器查看"
                    return code_info
            else:
                # 无法获取实现地址
                if code_info:
                    code_info["is_proxy"] = True
                    code_info["note"] = "这是代理合约，但无法获取实现合约地址"
    
    return code_info

