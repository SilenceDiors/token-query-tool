"""
EVM链合约代码获取模块
"""
import json
import re
import html
import requests
from typing import Optional, Dict, Any

from ..config import EVM_CHAINS


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
                
                return {
                    "verified": True,
                    "source_code": source_code,
                    "contract_name": contract_name or "Unknown",
                    "compiler_version": compiler_version or "",
                    "optimization_used": optimization_used or "",
                    "format": "single_file",
                    "method": "web_scraping"
                }
        else:
            return {
                "verified": False,
                "message": "源代码通过JavaScript动态加载，无法直接爬取",
                "web_url": explorer_urls[chain],
                "note": f"源代码在网页上可以直接查看（无需API key）\n   请访问: {explorer_urls[chain]}\n   或使用浏览器开发者工具查看源代码"
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


def get_evm_contract_code(token_address: str, chain: str = "ethereum", api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    获取EVM链合约源代码（直接从网页爬取，不需要API key）
    返回: dict包含源代码信息，如果无法获取则返回None
    """
    if chain not in EVM_CHAINS:
        return None
    
    # 直接使用网页爬取，不依赖API
    return get_evm_contract_code_from_webpage(token_address, chain)

