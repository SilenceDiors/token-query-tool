"""
Mythril 安全扫描模块
用于扫描 EVM 智能合约的安全漏洞（作为 Slither 的备选）
"""
import os
import sys
import tempfile
import subprocess
import json
import shutil
from typing import Optional, Dict, Any, Tuple

def ensure_package_installed(package_name: str, import_name: str = None) -> bool:
    """确保包已安装，如果未安装则自动安装"""
    import_name = import_name or package_name
    
    # 先尝试导入
    try:
        __import__(import_name)
        return True
    except ImportError:
        pass
    
    # 如果导入失败，尝试安装
    try:
        import subprocess
        import sys
        print(f"   正在自动安装 {package_name}...")
        sys.stdout.flush()
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', package_name],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode == 0:
            # 安装成功后再次尝试导入
            try:
                __import__(import_name)
                return True
            except ImportError:
                return False
        return False
    except Exception:
        return False


# 尝试导入 Mythril（如果未安装则自动安装）
MYTHRIL_AVAILABLE = False
if ensure_package_installed('mythril', 'mythril'):
    MYTHRIL_AVAILABLE = True


def scan_contract_with_mythril(contract_source: str, contract_name: str = "Contract", source_files: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """
    使用 Mythril 扫描合约
    
    参数:
        contract_source: Solidity 源代码（单文件）或主合约文件内容
        contract_name: 合约名称（可选）
        source_files: 多文件合约的字典 {文件名: 内容}（可选）
    
    返回:
        包含扫描结果的字典
    """
    if not MYTHRIL_AVAILABLE:
        return None
    
    try:
        # 创建临时文件
        if source_files and isinstance(source_files, dict) and len(source_files) > 1:
            # 多文件合约：创建临时目录
            temp_dir = tempfile.mkdtemp()
            temp_file = None
            
            try:
                # 找到主合约文件
                main_contract_filename = None
                for filename in source_files.keys():
                    if contract_name and contract_name.lower() in filename.lower():
                        main_contract_filename = filename
                        break
                if not main_contract_filename:
                    main_contract_filename = list(source_files.keys())[0]
                
                # 将所有文件写入临时目录
                for filename, content in source_files.items():
                    safe_filename = os.path.basename(filename)
                    if not safe_filename.endswith('.sol'):
                        safe_filename += '.sol'
                    target_path = os.path.join(temp_dir, safe_filename)
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    with open(target_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                
                # 主合约文件路径
                main_contract_base = os.path.basename(main_contract_filename)
                if not main_contract_base.endswith('.sol'):
                    main_contract_base += '.sol'
                temp_file = os.path.join(temp_dir, main_contract_base)
            except Exception as e:
                # 如果多文件处理失败，回退到单文件
                print(f"   ⚠️  多文件处理失败: {e}，回退到单文件模式")
                temp_dir = None
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                    f.write(contract_source)
                    temp_file = f.name
        else:
            # 单文件合约
            temp_dir = None
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                f.write(contract_source)
                temp_file = f.name
        
        try:
            # 尝试不同的 mythril 命令路径
            # Mythril 的正确命令格式是: python3 -m mythril analyze <file>
            mythril_cmd = None
            for cmd_base in [['python3', '-m', 'mythril'], ['python', '-m', 'mythril']]:
                try:
                    # 测试命令是否可用（尝试导入或运行简单命令）
                    test_result = subprocess.run(
                        cmd_base + ['analyze', '--help'],
                        capture_output=True,
                        timeout=5
                    )
                    # 即使返回码不是0，只要有输出就认为命令存在
                    if test_result.stdout or test_result.stderr:
                        mythril_cmd = cmd_base
                        break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            
            if not mythril_cmd:
                # 最后尝试：直接使用，让错误自然发生
                mythril_cmd = ['python3', '-m', 'mythril']
            
            # 构建命令: python3 -m mythril analyze <file>
            cmd_list = mythril_cmd + ['analyze', temp_file]
            
            # Mythril 可能支持 --json 或 -o json 选项，但不是所有版本都支持
            # 先尝试不使用格式选项，直接获取文本输出
            
            # 设置工作目录（如果是多文件）
            cwd = temp_dir if temp_dir else None
            
            print(f"   使用 Mythril 扫描合约...")
            sys.stdout.flush()
            
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=120,  # Mythril 可能需要更长时间
                cwd=cwd
            )
            
            output = result.stdout if result.stdout else ""
            error_output = result.stderr if result.stderr else ""
            
            # 尝试解析 JSON 输出
            if output:
                try:
                    # Mythril 可能输出多行 JSON 或混合输出
                    # 尝试提取 JSON 部分
                    json_start = output.find('{')
                    if json_start != -1:
                        json_str = output[json_start:]
                        # 找到最后一个 }
                        json_end = json_str.rfind('}')
                        if json_end != -1:
                            json_str = json_str[:json_end + 1]
                            data = json.loads(json_str)
                            return {
                                "tool": "mythril",
                                "data": data,
                                "raw_output": output,
                                "format": "json"
                            }
                except json.JSONDecodeError:
                    pass
            
            # 如果没有 JSON，返回文本输出
            if output or error_output:
                # 检查是否有错误
                full_output = output + "\n" + error_output
                if result.returncode != 0:
                    # 检查是否是编译错误
                    if "compilation" in full_output.lower() or "not found" in full_output.lower() or "error" in full_output.lower():
                        return {
                            "error": "Mythril 编译失败",
                            "message": f"Mythril 无法编译合约:\n{full_output[:500]}"
                        }
                
                # 检查是否有检测结果
                if any(keyword in full_output.lower() for keyword in ['vulnerability', 'issue', 'warning', 'detected', 'no issues']):
                    return {
                        "tool": "mythril",
                        "raw_output": full_output,
                        "format": "text"
                    }
                else:
                    # 没有检测结果，但也没有明显错误
                    return {
                        "tool": "mythril",
                        "raw_output": full_output,
                        "format": "text",
                        "no_issues": True
                    }
            
            return {
                "error": "无输出",
                "message": "Mythril 分析完成，但未产生输出"
            }
            
        finally:
            # 清理临时文件
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                
    except subprocess.TimeoutExpired:
        return {
            "error": "分析超时",
            "message": "Mythril 分析超过 120 秒"
        }
    except FileNotFoundError:
        return {
            "error": "Mythril 未找到",
            "message": "请确保已安装 mythril: pip install mythril"
        }
    except Exception as e:
        return {
            "error": str(e),
            "message": f"Mythril 分析失败: {e}"
        }


def format_mythril_results(results: Dict[str, Any]) -> str:
    """
    格式化 Mythril 扫描结果（美化输出，添加中文）
    """
    if "error" in results:
        return f"❌ Mythril 扫描失败: {results.get('message', results.get('error', '未知错误'))}"
    
    output_lines = []
    output_lines.append("")
    output_lines.append("╔══════════════════════════════════════════════════════════════════════════════╗")
    output_lines.append("║              🔍 Mythril 安全扫描结果                                        ║")
    output_lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
    
    if results.get("format") == "json" and "data" in results:
        data = results["data"]
        
        # Mythril JSON 格式可能包含 issues, errors, warnings 等
        issues = data.get("issues", [])
        errors = data.get("errors", [])
        warnings = data.get("warnings", [])
        
        if issues:
            output_lines.append("║  检测到的问题:                                                          ║")
            for i, issue in enumerate(issues, 1):
                title = issue.get("title", "未知问题")
                severity = issue.get("severity", "未知")
                description = issue.get("description", "")
                address = issue.get("address", "")
                
                # 翻译严重程度
                severity_map = {
                    "HIGH": "🔴 高危",
                    "MEDIUM": "🟡 中危",
                    "LOW": "🟢 低危",
                    "INFO": "ℹ️  信息"
                }
                severity_cn = severity_map.get(severity.upper(), severity)
                
                output_lines.append(f"║                                                                              ║")
                output_lines.append(f"║  {i}. {title}")
                output_lines.append(f"║     严重程度: {severity_cn}")
                if description:
                    # 截断过长的描述
                    desc = description[:200] + "..." if len(description) > 200 else description
                    output_lines.append(f"║     描述: {desc}")
                if address:
                    output_lines.append(f"║     位置: {address}")
        else:
            output_lines.append("║  ✅ 未检测到安全问题                                                      ║")
        
        if errors:
            output_lines.append("║                                                                              ║")
            output_lines.append("║  ⚠️  编译错误:")
            for error in errors[:5]:  # 只显示前5个错误
                output_lines.append(f"║     - {error}")
    
    elif results.get("format") == "text":
        # 解析文本输出
        raw_output = results.get("raw_output", "")
        if raw_output:
            # Mythril 文本输出通常包含漏洞信息
            lines = raw_output.split('\n')
            found_issues = False
            for line in lines:
                if any(keyword in line.upper() for keyword in ['VULNERABILITY', 'ISSUE', 'WARNING', 'ERROR']):
                    found_issues = True
                    output_lines.append(f"║  {line[:78]}")
            
            if not found_issues:
                output_lines.append("║  ✅ 未检测到安全问题                                                      ║")
    
    output_lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
    
    return "\n".join(output_lines)

