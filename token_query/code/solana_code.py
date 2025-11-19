"""
Solana程序代码获取模块
"""
import base64
import requests
from typing import Optional, Dict, Any, List

from ..config import RPC_ENDPOINTS

# 尝试导入 Capstone 反汇编引擎
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = None


def decode_base64_to_hex(base64_data: str) -> str:
    """将 base64 解码为十六进制字符串"""
    try:
        decoded_bytes = base64.b64decode(base64_data)
        return decoded_bytes.hex()
    except Exception as e:
        return f"解码失败: {e}"


def extract_bpf_from_elf(elf_bytes: bytes) -> Optional[bytes]:
    """
    从 ELF 文件中提取 BPF 字节码
    Solana 程序使用 ELF 格式，包含 BPF 字节码段
    """
    if not elf_bytes.startswith(b'\x7fELF'):
        return None
    
    # 简单尝试：查找 .text 段或其他包含代码的段
    # 这是一个简化的实现，完整的 ELF 解析需要专门的库
    try:
        # ELF 文件头在偏移 0x18 处有 e_shoff (section header offset)
        # 这里使用简单的启发式方法：查找常见的 BPF 指令模式
        # 实际应该使用 pyelftools 等库进行完整解析
        
        # 对于 Solana，BPF 代码通常在 .text 段
        # 尝试查找段头或直接搜索代码区域
        # 简化处理：返回整个文件（让 Capstone 尝试解析）
        return elf_bytes
    except:
        return None


def disassemble_bpf_bytecode(bytecode_bytes: bytes) -> List[Dict[str, Any]]:
    """
    使用 Capstone 引擎反汇编 BPF 字节码
    返回: 指令列表
    """
    if not CAPSTONE_AVAILABLE:
        return []
    
    # 检查是否是 ELF 格式
    is_elf = bytecode_bytes.startswith(b'\x7fELF')
    if is_elf:
        # 尝试从 ELF 中提取 BPF 代码
        bpf_code = extract_bpf_from_elf(bytecode_bytes)
        if bpf_code:
            bytecode_bytes = bpf_code
    
    try:
        # 创建 Capstone 实例，架构为 BPF
        md = capstone.Cs(capstone.CS_ARCH_BPF, capstone.CS_MODE_BPF_CLASSIC)
        md.detail = True
        
        instructions = []
        # 限制反汇编大小，避免处理过大的字节码（只处理前 10KB）
        max_size = min(len(bytecode_bytes), 10240)
        bytecode_to_disasm = bytecode_bytes[:max_size]
        
        for insn in md.disasm(bytecode_to_disasm, 0):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size
            })
        
        # 如果字节码很大，添加提示
        if len(bytecode_bytes) > max_size:
            instructions.append({
                "address": hex(max_size),
                "mnemonic": "...",
                "op_str": f"(仅显示前 {max_size} 字节，总共 {len(bytecode_bytes)} 字节)",
                "bytes": "",
                "size": 0
            })
        
        if instructions:
            return instructions
        
        # 如果 Classic 模式失败，尝试 Extended 模式
        md = capstone.Cs(capstone.CS_ARCH_BPF, capstone.CS_MODE_BPF_EXTENDED)
        md.detail = True
        
        for insn in md.disasm(bytecode_to_disasm, 0):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size
            })
        
        if len(bytecode_bytes) > max_size and instructions:
            instructions.append({
                "address": hex(max_size),
                "mnemonic": "...",
                "op_str": f"(仅显示前 {max_size} 字节)",
                "bytes": "",
                "size": 0
            })
        
        return instructions
    except Exception as e:
        # Capstone 可能不支持 BPF，或字节码格式不标准
        return []


def analyze_bpf_bytecode(bytecode_hex: str, bytecode_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """
    分析 BPF 字节码，提取基本信息
    注意：这是非常基础的分析，无法还原为完整源代码
    """
    analysis = {
        "bytecode_length": len(bytecode_hex) // 2,  # 字节数
        "hex_preview": bytecode_hex[:200] + "..." if len(bytecode_hex) > 200 else bytecode_hex,
        "note": "这是编译后的 BPF 字节码，无法直接还原为源代码"
    }
    
    # 尝试识别一些常见的 BPF 指令模式
    # BPF 指令通常是 8 字节对齐
    if len(bytecode_hex) % 16 == 0:  # 8 字节 = 16 个十六进制字符
        analysis["instruction_count"] = len(bytecode_hex) // 16
        analysis["format"] = "可能的 BPF 指令格式"
    
    # 如果 Capstone 可用，尝试反汇编
    if CAPSTONE_AVAILABLE and bytecode_bytes:
        disassembly = disassemble_bpf_bytecode(bytecode_bytes)
        if disassembly:
            analysis["disassembly"] = disassembly
            analysis["disassembly_count"] = len(disassembly)
            analysis["capstone_available"] = True
        else:
            analysis["capstone_available"] = True
            analysis["capstone_note"] = "Capstone 无法反汇编此字节码（可能不是标准 BPF 格式）"
    else:
        analysis["capstone_available"] = False
        if not CAPSTONE_AVAILABLE:
            analysis["capstone_note"] = "未安装 Capstone 引擎，无法反汇编。安装: pip install capstone"
    
    return analysis


def validate_solana_address(token_address: str) -> tuple[bool, Optional[str]]:
    """
    验证Solana地址格式
    返回: (is_valid, error_message)
    """
    token_address = token_address.strip()
    
    # Solana地址格式：base58编码，长度约32-44字符，不以0x开头
    if token_address.startswith("0x"):
        return False, "Solana地址格式错误：不应以 0x 开头（Solana使用base58编码）"
    
    if len(token_address) < 32:
        return False, f"Solana地址格式错误：长度过短（当前 {len(token_address)} 字符，应为32-44字符）"
    
    if len(token_address) > 44:
        return False, f"Solana地址格式错误：长度过长（当前 {len(token_address)} 字符，应为32-44字符）"
    
    # 验证是否为有效的base58字符
    base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not all(c in base58_chars for c in token_address):
        return False, "Solana地址格式错误：包含无效的base58字符"
    
    return True, None


def get_solana_program_code(token_address: str) -> Optional[Dict[str, Any]]:
    """
    获取Solana程序代码（账户数据）
    返回: dict包含程序账户数据信息
    """
    # 先验证地址格式
    is_valid, error_msg = validate_solana_address(token_address)
    if not is_valid:
        return {
            "verified": False,
            "message": error_msg or "Solana地址格式错误",
            "note": f"请检查地址是否正确：{token_address}\n   Solana地址应为base58编码，长度32-44字符"
        }
    
    rpc_url = RPC_ENDPOINTS["solana"]
    
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            token_address,
            {
                "encoding": "base64"
            }
        ]
    }
    
    try:
        response = requests.post(rpc_url, json=payload, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        # 检查RPC错误
        if result and "error" in result:
            error_code = result["error"].get("code", "")
            error_msg = result["error"].get("message", "")
            if "invalid" in error_msg.lower() or "not found" in error_msg.lower():
                return {
                    "verified": False,
                    "message": "地址不存在或无效",
                    "note": f"该Solana地址不存在：{token_address}\n   请检查地址是否正确"
                }
            return {
                "verified": False,
                "message": f"RPC请求失败: {error_msg}",
                "error": str(result["error"])
            }
        
        if result and "result" in result and result["result"]:
            account_info = result["result"]["value"]
            if account_info:
                data = account_info.get("data", [])
                executable = account_info.get("executable", False)
                owner = account_info.get("owner", "")
                
                # 检查是否是可执行程序
                if not executable:
                    return {
                        "verified": False,
                        "message": "该地址不是程序账户",
                        "note": f"该Solana地址存在但不是可执行程序账户\n   地址: {token_address}\n   如需查询代币信息，请使用代币账户地址"
                    }
                
                if isinstance(data, list) and len(data) > 0:
                    # data[0] 是 base64 编码的程序数据
                    program_data_base64 = data[0]
                    
                    # 解码 base64 为字节
                    bytecode_bytes = base64.b64decode(program_data_base64)
                    
                    # 解码 base64 为十六进制
                    bytecode_hex = bytecode_bytes.hex()
                    
                    # 分析字节码（包括反汇编）
                    analysis = analyze_bpf_bytecode(bytecode_hex, bytecode_bytes)
                    
                    note = "Solana程序代码是编译后的BPF字节码（base64编码），无法直接还原为源代码。"
                    if CAPSTONE_AVAILABLE and analysis.get("disassembly"):
                        note += "\n已使用 Capstone 引擎反汇编为汇编指令（见下方）。"
                    elif not CAPSTONE_AVAILABLE:
                        note += "\n提示: 安装 Capstone 引擎可进行反汇编: pip install capstone"
                    else:
                        note += "\n如需反编译，建议使用专业工具如 Ghidra、IDA Pro 或 Solana 专用反编译工具。"
                    
                    return {
                        "verified": True,
                        "source_code": program_data_base64,  # 保留原始 base64
                        "bytecode_hex": bytecode_hex,  # 十六进制格式
                        "bytecode_bytes": bytecode_bytes.hex(),  # 字节格式（用于反汇编）
                        "bytecode_analysis": analysis,  # 分析结果（包含反汇编）
                        "executable": executable,
                        "owner": owner,
                        "data_length": len(program_data_base64),
                        "format": "base64_bytecode",
                        "method": "rpc",
                        "note": note
                    }
        
        return {
            "verified": False,
            "message": "地址不存在或无效",
            "note": f"该Solana地址不存在：{token_address}\n   请检查地址是否正确"
        }
    except requests.exceptions.RequestException as e:
        return {
            "verified": False,
            "message": f"网络请求失败: {e}",
            "error": str(e),
            "note": "请检查网络连接或Solana RPC节点是否可用"
        }
    except Exception as e:
        return {
            "verified": False,
            "message": f"获取Solana程序代码失败: {e}",
            "error": str(e)
        }

