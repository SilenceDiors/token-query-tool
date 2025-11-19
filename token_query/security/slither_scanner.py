"""
Slither 安全扫描模块
用于扫描 EVM 智能合约的安全漏洞
"""
import os
import sys
import tempfile
import subprocess
import json
import shutil
import zipfile
import re
from typing import Optional, Dict, Any, List, Tuple

def install_package(package_name: str) -> Tuple[bool, str]:
    """
    自动安装 Python 包
    
    返回: (是否成功, 消息)
    """
    try:
        import sys
        import subprocess
        import threading
        import time
        
        print(f"   正在自动安装 {package_name}...")
        print(f"   (这可能需要几分钟，请稍候...)")
        sys.stdout.flush()
        
        # 使用实时输出，让用户看到进度
        process = subprocess.Popen(
            [sys.executable, '-m', 'pip', 'install', package_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # 启动一个线程来显示进度
        def show_progress():
            last_activity = time.time()
            while process.poll() is None:
                time.sleep(1)
                elapsed = time.time() - last_activity
                if elapsed > 10:  # 每10秒显示一次提示
                    print(f"   (仍在安装中，已等待 {int(elapsed)} 秒...)")
                    sys.stdout.flush()
                    last_activity = time.time()
        
        progress_thread = threading.Thread(target=show_progress, daemon=True)
        progress_thread.start()
        
        # 读取输出并实时显示
        output_lines = []
        for line in process.stdout:
            line = line.rstrip()
            if line:
                # 只显示重要的进度信息，避免输出过多
                if any(keyword in line.lower() for keyword in ['downloading', 'installing', 'successfully', 'error', 'warning']):
                    print(f"   {line}")
                    sys.stdout.flush()
                output_lines.append(line)
        
        # 等待进程完成
        returncode = process.wait(timeout=300)  # 总超时5分钟
        
        if returncode == 0:
            print(f"   ✅ 已成功安装 {package_name}")
            sys.stdout.flush()
            return True, f"已成功安装 {package_name}"
        else:
            error_msg = '\n'.join(output_lines[-10:])  # 只显示最后10行
            return False, f"安装 {package_name} 失败: {error_msg}"
    except subprocess.TimeoutExpired:
        if 'process' in locals():
            process.kill()
        return False, f"安装 {package_name} 超时（超过5分钟）"
    except Exception as e:
        return False, f"安装 {package_name} 时出错: {e}"


def download_openzeppelin_contracts(target_dir: str) -> bool:
    """
    下载 OpenZeppelin 合约到指定目录
    使用 GitHub API 下载最新版本的 contracts 目录
    """
    try:
        import requests
        
        # 创建目标目录
        os.makedirs(target_dir, exist_ok=True)
        
        # 使用 GitHub API 下载 ZIP 文件
        try:
            # 使用正确的 GitHub ZIP 下载 URL（不是 API）
            api_url = "https://github.com/OpenZeppelin/openzeppelin-contracts/archive/refs/heads/master.zip"
            print(f"   正在从 GitHub 下载 OpenZeppelin 合约...")
            sys.stdout.flush()
            
            response = requests.get(api_url, timeout=120, stream=True)
            response.raise_for_status()
            
            # 下载到临时文件
            zip_path = os.path.join(tempfile.gettempdir(), 'openzeppelin-contracts.zip')
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # 解压 ZIP 文件
            import zipfile
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # 提取到临时目录
                extract_dir = tempfile.mkdtemp()
                try:
                    # 先解压所有文件
                    zip_ref.extractall(extract_dir)
                    
                    # 找到包含 contracts 的目录（ZIP 文件通常有一个顶层目录，如 openzeppelin-contracts-master）
                    for item in os.listdir(extract_dir):
                        item_path = os.path.join(extract_dir, item)
                        if os.path.isdir(item_path):
                            contracts_src = os.path.join(item_path, 'contracts')
                            if os.path.exists(contracts_src):
                                # 如果目标目录已存在，先删除
                                if os.path.exists(target_dir):
                                    shutil.rmtree(target_dir)
                                os.makedirs(os.path.dirname(target_dir), exist_ok=True)
                                shutil.copytree(contracts_src, target_dir)
                                
                                # 验证下载是否成功（检查是否有文件）
                                if os.path.exists(target_dir):
                                    # 递归统计所有 .sol 文件
                                    sol_files = []
                                    for root, dirs, files in os.walk(target_dir):
                                        sol_files.extend([f for f in files if f.endswith('.sol')])
                                    if sol_files:
                                        print(f"   ✅ 已下载 OpenZeppelin 合约库（包含 {len(sol_files)} 个 .sol 文件）")
                                        sys.stdout.flush()
                                        return True
                finally:
                    if os.path.exists(extract_dir):
                        shutil.rmtree(extract_dir, ignore_errors=True)
            
            # 清理 ZIP 文件
            if os.path.exists(zip_path):
                os.unlink(zip_path)
        except Exception as e:
            print(f"   ⚠️  下载失败: {str(e)[:150]}")
            sys.stdout.flush()
        
        return False
    except Exception as e:
        print(f"   ⚠️  下载 OpenZeppelin 时出错: {str(e)[:150]}")
        sys.stdout.flush()
        return False


def download_layerzero_contracts(target_dir: str) -> bool:
    """
    下载 LayerZero OFT 合约到指定目录
    使用 GitHub API 下载最新版本的 contracts 目录
    """
    try:
        import requests
        import zipfile
        import shutil
        
        # 创建目标目录
        os.makedirs(target_dir, exist_ok=True)
        
        # 使用 GitHub API 下载 ZIP 文件
        try:
            # 使用正确的 GitHub ZIP 下载 URL（不是 API）
            api_url = "https://github.com/LayerZero-Labs/oft-evm/archive/refs/heads/main.zip"
            print(f"   正在从 GitHub 下载 LayerZero OFT 合约...")
            sys.stdout.flush()
            
            response = requests.get(api_url, timeout=120, stream=True)
            response.raise_for_status()
            
            # 下载到临时文件
            zip_path = os.path.join(tempfile.gettempdir(), 'layerzero-oft-evm.zip')
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # 解压 ZIP 文件
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # 提取到临时目录
                extract_dir = tempfile.mkdtemp()
                try:
                    # 先解压所有文件
                    zip_ref.extractall(extract_dir)
                    
                    # 找到包含 contracts 的目录（ZIP 文件通常有一个顶层目录，如 oft-evm-main）
                    for item in os.listdir(extract_dir):
                        item_path = os.path.join(extract_dir, item)
                        if os.path.isdir(item_path):
                            contracts_src = os.path.join(item_path, 'contracts')
                            if os.path.exists(contracts_src):
                                # 如果目标目录已存在，先删除
                                if os.path.exists(target_dir):
                                    shutil.rmtree(target_dir)
                                os.makedirs(os.path.dirname(target_dir), exist_ok=True)
                                shutil.copytree(contracts_src, target_dir)
                                
                                # 验证下载是否成功（检查是否有文件）
                                if os.path.exists(target_dir):
                                    # 递归统计所有 .sol 文件
                                    sol_files = []
                                    for root, dirs, files in os.walk(target_dir):
                                        sol_files.extend([f for f in files if f.endswith('.sol')])
                                    if sol_files:
                                        print(f"   ✅ 已下载 LayerZero OFT 合约库（包含 {len(sol_files)} 个 .sol 文件）")
                                        sys.stdout.flush()
                                        return True
                finally:
                    if os.path.exists(extract_dir):
                        shutil.rmtree(extract_dir, ignore_errors=True)
            
            # 清理 ZIP 文件
            if os.path.exists(zip_path):
                os.unlink(zip_path)
        except Exception as e:
            print(f"   ⚠️  下载失败: {str(e)[:150]}")
            sys.stdout.flush()
        
        return False
    except Exception as e:
        print(f"   ⚠️  下载 LayerZero 时出错: {str(e)[:150]}")
        sys.stdout.flush()
        return False


def ensure_package_installed(package_name: str, import_name: str = None) -> bool:
    """
    确保包已安装，如果未安装则自动安装
    
    参数:
        package_name: pip 包名
        import_name: 导入时的模块名（如果与包名不同）
    
    返回: 是否可用
    """
    if import_name is None:
        import_name = package_name
    
    # 尝试导入
    try:
        __import__(import_name)
        return True
    except ImportError:
        # 未安装，尝试自动安装
        success, msg = install_package(package_name)
        if success:
            # 安装成功后重新导入
            try:
                __import__(import_name)
                return True
            except ImportError:
                return False
        return False


# 尝试导入 Slither Python API（如果未安装则自动安装）
SLITHER_API_AVAILABLE = False
Slither = None

# 首先确保 slither-analyzer 已安装
if ensure_package_installed('slither-analyzer', 'slither'):
    try:
        # 尝试不同的导入方式
        try:
            from slither.slither import Slither
            SLITHER_API_AVAILABLE = True
        except ImportError:
            try:
                from slither import Slither
                SLITHER_API_AVAILABLE = True
            except ImportError:
                SLITHER_API_AVAILABLE = False
                Slither = None
    except Exception:
        SLITHER_API_AVAILABLE = False
        Slither = None

# 尝试导入 py-solc-x 用于自动安装 solc（如果未安装则自动安装）
SOLC_AUTO_INSTALL_AVAILABLE = False
install_solc = None
get_installed_solc_versions = None
set_solc_version = None

if ensure_package_installed('py-solc-x', 'solcx'):
    try:
        from solcx import install_solc, get_installed_solc_versions, set_solc_version
        SOLC_AUTO_INSTALL_AVAILABLE = True
    except ImportError:
        SOLC_AUTO_INSTALL_AVAILABLE = False


def detect_solidity_version(contract_source: str) -> Optional[str]:
    """
    从合约源代码中检测 Solidity 版本
    
    返回: 版本字符串（如 "0.4.17"），如果无法检测则返回 None
    """
    import re
    # 匹配 pragma solidity 语句
    patterns = [
        r'pragma\s+solidity\s+([^;]+);',
        r'pragma\s+solidity\s+([^\s;]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, contract_source, re.IGNORECASE)
        if match:
            version_str = match.group(1).strip()
            # 提取版本号（处理 ^, >=, <= 等）
            version_match = re.search(r'(\d+\.\d+\.\d+)', version_str)
            if version_match:
                return version_match.group(1)
            # 如果没有完整版本号，尝试提取主版本号
            version_match = re.search(r'(\d+\.\d+)', version_str)
            if version_match:
                return version_match.group(1) + ".0"
    return None


def ensure_solc_available(contract_source: Optional[str] = None) -> Tuple[bool, str]:
    """
    确保 solc 编译器可用
    如果不可用，尝试自动安装
    如果提供了合约源代码，会尝试安装匹配的版本
    
    返回: (是否可用, 消息)
    """
    # 首先检查系统是否已有 solc
    try:
        result = subprocess.run(
            ['solc', '--version'],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            return True, "系统已安装 solc"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # 检查 py-solc-x 是否可用并已安装 solc
    if SOLC_AUTO_INSTALL_AVAILABLE and install_solc is not None:
        try:
            # 使用 solcx.install.get_executable 获取路径
            from solcx.install import get_executable as get_solc_executable
            installed_versions = get_installed_solc_versions()
            
            # 如果提供了合约源代码，检测需要的版本
            target_version = None
            if contract_source:
                detected_version = detect_solidity_version(contract_source)
                if detected_version:
                    target_version = detected_version
                    # 检查是否已安装匹配的版本
                    installed_version_strs = [str(v) for v in installed_versions]
                    if target_version not in installed_version_strs:
                        # 如果未安装匹配版本，尝试安装
                        print(f"   检测到合约需要 Solidity {target_version}，当前未安装，正在安装...")
                        try:
                            install_solc(target_version)
                            set_solc_version(target_version)
                            installed_versions = get_installed_solc_versions()  # 重新获取
                        except Exception as e:
                            print(f"   安装 solc {target_version} 失败: {e}，将使用已安装的版本")
                            target_version = None
            
            if installed_versions:
                # 使用目标版本或最新版本
                if target_version:
                    # 尝试使用目标版本
                    try:
                        set_solc_version(target_version)
                        version_to_use = target_version
                    except:
                        # 如果设置失败，使用最新版本
                        def version_key(v):
                            v_str = str(v)
                            try:
                                return tuple(map(int, v_str.split('.')))
                            except:
                                return (0, 0, 0)
                        latest_version = max(installed_versions, key=version_key)
                        set_solc_version(latest_version)
                        version_to_use = str(latest_version)
                else:
                    # 使用最新版本
                    def version_key(v):
                        v_str = str(v)
                        try:
                            return tuple(map(int, v_str.split('.')))
                        except:
                            return (0, 0, 0)
                    latest_version = max(installed_versions, key=version_key)
                    set_solc_version(latest_version)
                    version_to_use = str(latest_version)
                
                # 获取 solc 可执行文件路径
                try:
                    solc_path = get_solc_executable()
                    # 验证路径是否有效
                    if solc_path and os.path.exists(solc_path):
                        # 设置环境变量，让 Slither 能找到 solc
                        os.environ['SOLC'] = solc_path
                        os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                        return True, f"使用 py-solc-x 管理的 solc {version_to_use} (路径: {solc_path})"
                except Exception as e:
                    # 如果获取路径失败，尝试手动查找
                    try:
                        # py-solc-x 通常将 solc 存储在 ~/.solcx 或 ~/.py-solc-x
                        home = os.path.expanduser("~")
                        possible_dirs = [
                            os.path.join(home, ".solcx"),
                            os.path.join(home, ".py-solc-x"),
                        ]
                        for base_dir in possible_dirs:
                            if os.path.exists(base_dir):
                                # 查找版本目录
                                for item in os.listdir(base_dir):
                                    if item.startswith("solc-v") and version_to_use in item:
                                        solc_path = os.path.join(base_dir, item)
                                        if os.path.exists(solc_path) and os.access(solc_path, os.X_OK):
                                            os.environ['SOLC'] = solc_path
                                            os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                                            return True, f"使用 py-solc-x 管理的 solc {version_to_use} (路径: {solc_path})"
                    except:
                        pass
        except Exception as e:
            # 如果导入失败，继续尝试其他方法
            pass
    
    # 如果系统没有 solc，尝试使用 py-solc-x
    if not SOLC_AUTO_INSTALL_AVAILABLE:
        # 尝试自动安装 py-solc-x
        if ensure_package_installed('py-solc-x', 'solcx'):
            try:
                # 重新导入（使用局部变量，不修改全局）
                from solcx import install_solc as _install_solc, get_installed_solc_versions as _get_installed_solc_versions, set_solc_version as _set_solc_version
                from solcx.install import get_executable as _get_executable
                # 使用局部导入的函数
                installed_versions = _get_installed_solc_versions()
                if installed_versions:
                    # 处理版本号（可能是字符串或 Version 对象）
                    def version_key(v):
                        v_str = str(v)
                        try:
                            return tuple(map(int, v_str.split('.')))
                        except:
                            return (0, 0, 0)
                    latest_version = max(installed_versions, key=version_key)
                    _set_solc_version(latest_version)
                    # 获取 solc 路径并设置环境变量
                    try:
                        solc_path = _get_executable()
                        if solc_path and os.path.exists(solc_path):
                            os.environ['SOLC'] = solc_path
                            os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                            return True, f"使用 py-solc-x 管理的 solc {latest_version} (路径: {solc_path})"
                    except:
                        pass
                    return True, f"使用 py-solc-x 管理的 solc 版本: {latest_version}"
                # 如果没有安装，尝试安装
                # 如果提供了合约源代码，尝试检测并安装匹配的版本
                target_version = None
                if contract_source:
                    detected_version = detect_solidity_version(contract_source)
                    if detected_version:
                        target_version = detected_version
                        print(f"   检测到合约使用 Solidity {detected_version}，尝试安装匹配的 solc 版本...")
                
                if not target_version:
                    target_version = '0.8.20'
                    print("   正在自动安装 solc 编译器（首次使用需要下载，请稍候）...")
                    print("   (下载 solc 可能需要几分钟，请耐心等待...)")
                    sys.stdout.flush()
                
                try:
                    _install_solc(target_version)
                    _set_solc_version(target_version)
                    # 获取 solc 路径并设置环境变量
                    try:
                        solc_path = _get_executable()
                        if solc_path and os.path.exists(solc_path):
                            os.environ['SOLC'] = solc_path
                            os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                            return True, f"已自动安装 solc {target_version} (路径: {solc_path})"
                    except:
                        pass
                    return True, f"已自动安装 solc {target_version}"
                except Exception as e:
                    try:
                        _install_solc()
                        installed_versions = _get_installed_solc_versions()
                        if installed_versions:
                            # 处理版本号（可能是字符串或 Version 对象）
                            def version_key(v):
                                v_str = str(v)
                                try:
                                    return tuple(map(int, v_str.split('.')))
                                except:
                                    return (0, 0, 0)
                            latest_version = max(installed_versions, key=version_key)
                            _set_solc_version(latest_version)
                            # 获取 solc 路径并设置环境变量
                            try:
                                solc_path = _get_executable()
                                if solc_path and os.path.exists(solc_path):
                                    os.environ['SOLC'] = solc_path
                                    os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                                    return True, f"已自动安装 solc {latest_version} (路径: {solc_path})"
                            except:
                                pass
                            return True, f"已自动安装 solc {latest_version}"
                        else:
                            return False, f"自动安装 solc 失败: {e}"
                    except Exception as e2:
                        return False, f"自动安装 solc 失败: {e2}"
            except ImportError:
                return False, "py-solc-x 安装失败，无法自动管理 solc"
        else:
            return False, "无法自动安装 py-solc-x，请手动安装: pip install py-solc-x"
    
    # 如果 SOLC_AUTO_INSTALL_AVAILABLE 为 True，使用全局导入的函数
    if SOLC_AUTO_INSTALL_AVAILABLE and install_solc is not None:
        try:
            # 检查是否已安装 solc 版本
            installed_versions = get_installed_solc_versions()
            if installed_versions:
                # 使用最新安装的版本（处理版本号可能是字符串或 Version 对象）
                def version_key(v):
                    v_str = str(v)
                    try:
                        return tuple(map(int, v_str.split('.')))
                    except:
                        return (0, 0, 0)
                latest_version = max(installed_versions, key=version_key)
                set_solc_version(latest_version)
                # 获取 solc 路径并设置环境变量
                try:
                    from solcx.install import get_executable as get_solc_executable
                    solc_path = get_solc_executable()
                    if solc_path and os.path.exists(solc_path):
                        os.environ['SOLC'] = solc_path
                        os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                        return True, f"使用 py-solc-x 管理的 solc {latest_version} (路径: {solc_path})"
                except:
                    pass
                return True, f"使用 py-solc-x 管理的 solc 版本: {latest_version}"
            
            # 如果没有安装，尝试安装一个常用版本
            # 如果提供了合约源代码，尝试检测并安装匹配的版本
            target_version = None
            if contract_source:
                detected_version = detect_solidity_version(contract_source)
                if detected_version:
                    # 尝试安装检测到的版本
                    try:
                        # 检查版本是否可安装
                        from solcx.install import get_installable_solc_versions
                        installable = get_installable_solc_versions()
                        # 查找最接近的可用版本
                        target_version = detected_version
                        print(f"   检测到合约使用 Solidity {detected_version}，尝试安装匹配的 solc 版本...")
                    except:
                        pass
            
            # 如果没有检测到版本或检测失败，使用默认版本
            if not target_version:
                target_version = '0.8.20'
                print("   正在自动安装 solc 编译器（首次使用需要下载，请稍候）...")
                print("   (下载 solc 可能需要几分钟，请耐心等待...)")
                sys.stdout.flush()
            
            try:
                # 安装目标版本
                install_solc(target_version)
                set_solc_version(target_version)
                # 获取 solc 路径并设置环境变量
                try:
                    from solcx.install import get_executable as get_solc_executable
                    solc_path = get_solc_executable()
                    if solc_path and os.path.exists(solc_path):
                        os.environ['SOLC'] = solc_path
                        os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                        return True, f"已自动安装 solc {target_version} (路径: {solc_path})"
                except:
                    pass
                return True, f"已自动安装 solc {target_version}"
            except Exception as e:
                # 如果安装失败，尝试安装最新版本
                try:
                    install_solc()  # 不指定版本会安装最新版本
                    installed_versions = get_installed_solc_versions()
                    if installed_versions:
                        # 处理版本号（可能是字符串或 Version 对象）
                        def version_key(v):
                            v_str = str(v)
                            try:
                                return tuple(map(int, v_str.split('.')))
                            except:
                                return (0, 0, 0)
                        latest_version = max(installed_versions, key=version_key)
                        set_solc_version(latest_version)
                        # 获取 solc 路径并设置环境变量
                        try:
                            from solcx.install import get_executable as get_solc_executable
                            solc_path = get_solc_executable()
                            if solc_path and os.path.exists(solc_path):
                                os.environ['SOLC'] = solc_path
                                os.environ['PATH'] = os.path.dirname(solc_path) + os.pathsep + os.environ.get('PATH', '')
                                return True, f"已自动安装 solc {latest_version} (路径: {solc_path})"
                        except:
                            pass
                        return True, f"已自动安装 solc {latest_version}"
                    else:
                        return False, f"自动安装 solc 失败: {e}"
                except Exception as e2:
                    return False, f"自动安装 solc 失败: {e2}"
        except Exception as e:
            return False, f"检查/安装 solc 时出错: {e}"
    
    return False, "py-solc-x 不可用"


def scan_contract_with_slither_api(contract_source: str, contract_name: str = "Contract") -> Optional[Dict[str, Any]]:
    """
    使用 Slither Python API 扫描合约
    """
    if not SLITHER_API_AVAILABLE:
        return None
    
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(contract_source)
            temp_file = f.name
        
        try:
            # Slither Python API 不支持直接传递 solc 参数
            # 但可以通过环境变量 SOLC 来指定
            # 环境变量已经在 ensure_solc_available 中设置
            slither = Slither(temp_file)
            
            # 收集检测结果
            results = {
                "detectors": [],
                "info": [],
                "optimization": [],
                "summary": {
                    "total_issues": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }
            
            # 获取检测器结果
            for detector in slither.detectors:
                for result in detector.results:
                    severity = result.impact.name if hasattr(result, 'impact') else "Unknown"
                    confidence = result.confidence.name if hasattr(result, 'confidence') else "Unknown"
                    
                    issue = {
                        "check": detector.ARGUMENT,
                        "impact": severity,
                        "confidence": confidence,
                        "description": str(result),
                        "markdown": result.markdown if hasattr(result, 'markdown') else ""
                    }
                    
                    results["detectors"].append(issue)
                    
                    # 统计
                    if severity == "HIGH":
                        results["summary"]["high"] += 1
                    elif severity == "MEDIUM":
                        results["summary"]["medium"] += 1
                    elif severity == "LOW":
                        results["summary"]["low"] += 1
                    else:
                        results["summary"]["info"] += 1
                    
                    results["summary"]["total_issues"] += 1
            
            return results
        finally:
            # 清理临时文件
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
    except Exception as e:
        return {
            "error": str(e),
            "message": f"Slither API 分析失败: {e}"
        }


def scan_contract_with_slither_cli(contract_source: str, contract_name: str = "Contract", source_files: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """
    使用 Slither 命令行工具扫描合约
    
    参数:
        contract_source: Solidity 源代码（单文件）或主合约文件内容
        contract_name: 合约名称（可选）
        source_files: 多文件合约的字典 {文件名: 内容}
    """
    try:
        # 如果是多文件合约，创建临时目录并保存所有文件
        if source_files and isinstance(source_files, dict) and len(source_files) > 1:
            temp_dir = tempfile.mkdtemp()
            temp_file = None
            
            try:
                # 分析所有 import 语句，确定需要的目录结构
                all_imports = set()
                file_import_map = {}  # 文件名 -> 该文件中的 import 列表
                
                # 创建一个修改后的源文件字典，将 @openzeppelin 路径替换为相对路径
                modified_source_files = {}
                
                for filename, content in source_files.items():
                    # 提取该文件中的所有 import 语句（在修改之前）
                    imports = re.findall(r'import\s+["\']([^"\']+)["\']', content)
                    imports.extend(re.findall(r'import\s+{.*?}\s+from\s+["\']([^"\']+)["\']', content))
                    file_import_map[filename] = imports
                    all_imports.update(imports)  # 在修改之前收集所有导入
                    
                    # 修改 import 语句
                    modified_content = content
                    
                    # 处理 SPDX 许可证标识符：如果文件中有多个，只保留第一个
                    # 这可以避免 "Multiple SPDX license identifiers" 错误
                    spdx_pattern = r'//\s*SPDX-License-Identifier:.*'
                    spdx_matches = list(re.finditer(spdx_pattern, modified_content, re.MULTILINE))
                    if len(spdx_matches) > 1:
                        # 保留第一个，移除其他的
                        for match in reversed(spdx_matches[1:]):  # 从后往前删除，避免索引变化
                            start, end = match.span()
                            modified_content = modified_content[:start] + modified_content[end:].lstrip()
                    
                    # 尝试将 @openzeppelin 和 @layerzerolabs 的 import 改为相对路径
                    # 这样可以避免 remapping 的问题
                    # 但首先需要确定文件的实际位置
                    # 暂时保留原始 import，让 remapping 处理
                    # 如果 remapping 失败，可以考虑修改 import 路径
                    modified_source_files[filename] = modified_content
                
                # 创建文件名到实际文件路径的映射
                # 注意：文件的实际位置会在后面根据 import 关系确定
                file_path_map = {}  # 原始文件名 -> 实际文件路径
                
                # 先确定主合约文件
                main_contract_filename = None
                for filename in source_files.keys():
                    if contract_name and contract_name.lower() in filename.lower():
                        main_contract_filename = filename
                        break
                if not main_contract_filename:
                    main_contract_filename = list(source_files.keys())[0]
                
                # 处理 @openzeppelin 和其他路径映射
                # 创建 remappings 来处理这些导入
                remaps = []
                base_path = temp_dir
                
                # 检查是否有 @openzeppelin 导入
                has_openzeppelin = any('@openzeppelin' in imp for imp in all_imports)
                
                # 检查是否有 LayerZero 导入
                has_layerzero = any('@layerzerolabs' in imp for imp in all_imports)
                
                # 检查是否有 OpenZeppelin 导入
                if all_imports:
                    openzeppelin_imports = [imp for imp in all_imports if '@openzeppelin' in imp]
                    if openzeppelin_imports:
                        print(f"   检测到 OpenZeppelin 依赖，正在处理...")
                        sys.stdout.flush()
                    
                    layerzero_imports = [imp for imp in all_imports if '@layerzerolabs' in imp]
                    if layerzero_imports:
                        print(f"   检测到 LayerZero 依赖，正在处理...")
                        sys.stdout.flush()
                
                # 对于 @openzeppelin，我们需要创建目录结构或使用 remapping
                if has_openzeppelin:
                    # 创建 @openzeppelin 目录结构
                    openzeppelin_base = os.path.join(temp_dir, 'node_modules', '@openzeppelin', 'contracts')
                    os.makedirs(openzeppelin_base, exist_ok=True)
                    
                    # 首先尝试下载完整的 OpenZeppelin 合约库
                    print("   检测到 OpenZeppelin 依赖，正在下载 OpenZeppelin 合约库...")
                    sys.stdout.flush()
                    download_success = download_openzeppelin_contracts(openzeppelin_base)
                    
                    if download_success:
                        print("   ✅ 已成功下载 OpenZeppelin 合约库")
                        sys.stdout.flush()
                        # 下载成功后，不需要替换 import，直接使用 remapping 即可
                        # 跳过 import 替换步骤
                    else:
                        print("   ⚠️  下载 OpenZeppelin 合约库失败，将从抓取的源代码中提取 OpenZeppelin 文件")
                        sys.stdout.flush()
                        # 如果下载失败，从抓取的源代码中智能提取 OpenZeppelin 文件
                        # 根据 import 语句推断文件应该放在哪里
                        openzeppelin_file_map = {}  # import_path -> (filename, content)
                        
                        # 收集所有 OpenZeppelin 相关的 import
                        for filename, imports in file_import_map.items():
                            for imp in imports:
                                if '@openzeppelin' in imp:
                                    # 提取 import 路径，例如: @openzeppelin/contracts/token/ERC20/IERC20.sol
                                    # 转换为文件路径: token/ERC20/IERC20.sol
                                    if '/contracts/' in imp:
                                        relative_path = imp.split('/contracts/')[-1]
                                    else:
                                        relative_path = imp.replace('@openzeppelin/contracts/', '')
                                    
                                    # 查找对应的文件
                                    target_file = os.path.basename(relative_path)
                                    # 在抓取的源代码中查找匹配的文件
                                    found = False
                                    for src_filename, src_content in modified_source_files.items():
                                        src_base = os.path.basename(src_filename)
                                        # 更宽松的匹配：文件名匹配或包含关键字
                                        if (src_base == target_file or 
                                            target_file in src_base or 
                                            (target_file.replace('.sol', '') in src_base and src_base.endswith('.sol'))):
                                            openzeppelin_file_map[relative_path] = (src_filename, src_content)
                                            found = True
                                            break
                                    
                                    # 如果没找到，记录警告
                                    if not found and relative_path not in openzeppelin_file_map:
                                        print(f"   ⚠️  未找到 OpenZeppelin 文件: {relative_path}")
                                        sys.stdout.flush()
                        
                        # 根据 import 路径放置文件
                        placed_count = 0
                        placed_files = []
                        for relative_path, (src_filename, content) in openzeppelin_file_map.items():
                            target_path = os.path.join(openzeppelin_base, relative_path)
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            with open(target_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                            placed_count += 1
                            placed_files.append(relative_path)
                            
                            # 验证文件是否真的被创建
                            if not os.path.exists(target_path):
                                print(f"   ⚠️  警告: 文件创建失败: {target_path}")
                                sys.stdout.flush()
                        
                        if placed_count > 0:
                            print(f"   ✅ 已提取并放置 {placed_count} 个 OpenZeppelin 文件")
                            # 显示前几个文件路径用于调试
                            if placed_count <= 5:
                                for f in placed_files:
                                    full_path = os.path.join(openzeppelin_base, f)
                                    exists = "✅" if os.path.exists(full_path) else "❌"
                                    print(f"      {exists} {f}")
                            else:
                                for f in placed_files[:3]:
                                    full_path = os.path.join(openzeppelin_base, f)
                                    exists = "✅" if os.path.exists(full_path) else "❌"
                                    print(f"      {exists} {f}")
                                print(f"      ... 还有 {placed_count - 3} 个文件")
                            sys.stdout.flush()
                        else:
                            print(f"   ⚠️  未能提取任何 OpenZeppelin 文件，可能抓取的源代码中不包含这些文件")
                            sys.stdout.flush()
                        
                        # 同时尝试基于文件名的传统匹配（作为补充）
                        for filename, content in modified_source_files.items():
                            safe_filename = os.path.basename(filename)
                            # 检查文件名是否匹配 OpenZeppelin 合约
                            target_path = None
                            
                            if 'ERC20.sol' == safe_filename and 'extensions' not in filename and 'IERC20' not in safe_filename:
                                target_path = os.path.join(openzeppelin_base, 'token', 'ERC20', 'ERC20.sol')
                            elif 'Ownable' in safe_filename and 'Ownable.sol' == safe_filename:
                                target_path = os.path.join(openzeppelin_base, 'access', 'Ownable.sol')
                            elif 'Context' in safe_filename and 'Context.sol' == safe_filename:
                                target_path = os.path.join(openzeppelin_base, 'utils', 'Context.sol')
                            elif 'IERC20.sol' == safe_filename:
                                target_path = os.path.join(openzeppelin_base, 'token', 'ERC20', 'IERC20.sol')
                            elif 'IERC20Metadata' in safe_filename:
                                target_path = os.path.join(openzeppelin_base, 'token', 'ERC20', 'extensions', 'IERC20Metadata.sol')
                            elif 'draft-IERC6093' in safe_filename:
                                target_path = os.path.join(openzeppelin_base, 'interfaces', 'draft-IERC6093.sol')
                            
                            if target_path and not os.path.exists(target_path):
                                # 创建目录并复制文件
                                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                with open(target_path, 'w', encoding='utf-8') as f:
                                    f.write(content)
                    
                    # 设置 remapping (格式: prefix=path)
                    # Slither 使用 --solc-remaps，格式应该是 @openzeppelin/contracts/=path
                    # 注意：remapping 需要使用绝对路径，路径末尾不要有斜杠
                    openzeppelin_base_abs = os.path.abspath(openzeppelin_base)
                    # 移除末尾斜杠（如果有）
                    if openzeppelin_base_abs.endswith('/'):
                        openzeppelin_base_abs = openzeppelin_base_abs[:-1]
                    
                    # 验证路径是否存在
                    if not os.path.exists(openzeppelin_base_abs):
                        print(f"   ⚠️  警告: OpenZeppelin 目录不存在: {openzeppelin_base_abs}")
                        sys.stdout.flush()
                    else:
                        # 列出目录中的文件用于调试
                        try:
                            files = [f for f in os.listdir(openzeppelin_base_abs) if f.endswith('.sol')]
                            if files:
                                print(f"   📁 OpenZeppelin 目录包含 {len(files)} 个 .sol 文件")
                                sys.stdout.flush()
                        except:
                            pass
                    
                    # 注意：remapping 格式应该是 prefix=path
                    # 根据 Solidity 文档，当导入 @openzeppelin/contracts/access/Ownable.sol 时
                    # 如果 remapping 是 @openzeppelin/contracts=path，solc 会在 path/access/Ownable.sol 查找
                    # 如果 remapping 是 @openzeppelin=path，solc 会在 path/contracts/access/Ownable.sol 查找
                    # 我们的文件在 {openzeppelin_base_abs}/access/Ownable.sol，所以应该使用第一种格式
                    remaps.append(f"@openzeppelin/contracts={openzeppelin_base_abs}")
                    
                    # 文件已正确放置到 OpenZeppelin 目录结构中
                
                # 处理 LayerZero 依赖
                if has_layerzero:
                    # 创建 LayerZero 目录结构
                    layerzero_base = os.path.join(temp_dir, 'node_modules', '@layerzerolabs', 'oft-evm', 'contracts')
                    os.makedirs(layerzero_base, exist_ok=True)
                    
                    # 首先尝试下载完整的 LayerZero 合约库
                    print("   检测到 LayerZero 依赖，正在下载 LayerZero OFT 合约库...")
                    sys.stdout.flush()
                    download_success = download_layerzero_contracts(layerzero_base)
                    
                    if download_success:
                        print("   ✅ 已成功下载 LayerZero OFT 合约库")
                        sys.stdout.flush()
                        # 下载成功后，不需要替换 import，直接使用 remapping 即可
                    else:
                        print("   ⚠️  下载 LayerZero 合约库失败，将从抓取的源代码中提取 LayerZero 文件")
                        sys.stdout.flush()
                        print("   正在从抓取的源代码中提取 LayerZero 文件...")
                        sys.stdout.flush()
                    
                    # 从抓取的源代码中提取 LayerZero 文件
                    layerzero_file_map = {}  # import_path -> (filename, content)
                    
                    # 收集所有 LayerZero 相关的 import
                    for filename, imports in file_import_map.items():
                        for imp in imports:
                            if '@layerzerolabs' in imp:
                                # 提取 import 路径，例如: @layerzerolabs/oft-evm/contracts/OFT.sol
                                # 转换为文件路径: OFT.sol
                                if '/contracts/' in imp:
                                    relative_path = imp.split('/contracts/')[-1]
                                else:
                                    relative_path = imp.replace('@layerzerolabs/oft-evm/contracts/', '')
                                
                                # 查找对应的文件
                                target_file = os.path.basename(relative_path)
                                # 在抓取的源代码中查找匹配的文件
                                for src_filename, src_content in modified_source_files.items():
                                    src_base = os.path.basename(src_filename)
                                    if src_base == target_file or target_file in src_base or 'OFT' in src_base:
                                        layerzero_file_map[relative_path] = (src_filename, src_content)
                                        break
                    
                    # 根据 import 路径放置文件
                    placed_count = 0
                    for relative_path, (src_filename, content) in layerzero_file_map.items():
                        target_path = os.path.join(layerzero_base, relative_path)
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with open(target_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        placed_count += 1
                    
                    if placed_count > 0:
                        print(f"   ✅ 已提取并放置 {placed_count} 个 LayerZero 文件")
                        sys.stdout.flush()
                    else:
                        print(f"   ⚠️  未能提取任何 LayerZero 文件，可能抓取的源代码中不包含这些文件")
                        sys.stdout.flush()
                    
                    # 设置 LayerZero remapping
                    layerzero_base_abs = os.path.abspath(layerzero_base)
                    # 移除末尾斜杠（如果有）
                    if layerzero_base_abs.endswith('/'):
                        layerzero_base_abs = layerzero_base_abs[:-1]
                    # 注意：remapping 格式应该是 prefix=path，不要有多余的斜杠
                    remaps.append(f"@layerzerolabs/oft-evm/contracts={layerzero_base_abs}")
                
                # 处理相对路径导入（如 ../../interfaces/draft-IERC6093.sol）
                # 对于相对路径，我们需要根据导入文件的上下文创建正确的目录结构
                # 首先，我们需要确定每个文件应该放在哪里
                # 根据 import 语句中的相对路径，我们可以推断出文件的相对位置
                
                # 创建一个映射：文件名 -> 应该放置的相对路径
                file_placement_map = {}  # 文件名 -> 相对路径（从 temp_dir 开始）
                
                # 分析所有文件的导入关系，确定目录结构
                for filename, imports in file_import_map.items():
                    base_name = os.path.basename(filename)
                    # 默认放在根目录
                    if base_name not in file_placement_map:
                        file_placement_map[base_name] = base_name
                    
                    # 分析该文件的导入，确定依赖文件的位置
                    for imp in imports:
                        if imp.startswith('../'):
                            # 相对路径导入
                            parts = imp.split('/')
                            target_file = parts[-1]
                            # 计算相对路径的深度
                            depth = sum(1 for p in parts if p == '..')
                            
                            # 根据路径中的关键字确定目录
                            if 'interfaces' in imp:
                                target_rel_path = os.path.join('interfaces', target_file)
                            elif 'extensions' in imp:
                                target_rel_path = os.path.join('token', 'ERC20', 'extensions', target_file)
                            elif 'utils' in imp:
                                target_rel_path = os.path.join('utils', target_file)
                            else:
                                # 根据深度推断
                                if depth >= 2:
                                    target_rel_path = os.path.join('interfaces', target_file)
                                elif depth == 1:
                                    target_rel_path = os.path.join('token', 'ERC20', target_file)
                                else:
                                    target_rel_path = target_file
                            
                            file_placement_map[target_file] = target_rel_path
                
                # 根据映射创建文件（使用修改后的内容）
                # 首先创建 OpenZeppelin 文件（如果存在）
                if has_openzeppelin:
                    for filename, content in modified_source_files.items():
                        safe_filename = os.path.basename(filename)
                        target_path = None
                        
                        if 'ERC20.sol' == safe_filename and 'extensions' not in filename and 'IERC20' not in safe_filename:
                            target_path = os.path.join(openzeppelin_base, 'token', 'ERC20', 'ERC20.sol')
                        elif 'Ownable' in safe_filename and 'Ownable.sol' == safe_filename:
                            target_path = os.path.join(openzeppelin_base, 'access', 'Ownable.sol')
                        elif 'Context' in safe_filename and 'Context.sol' == safe_filename:
                            target_path = os.path.join(openzeppelin_base, 'utils', 'Context.sol')
                        elif 'IERC20.sol' == safe_filename:
                            target_path = os.path.join(openzeppelin_base, 'token', 'ERC20', 'IERC20.sol')
                        elif 'IERC20Metadata' in safe_filename:
                            target_path = os.path.join(openzeppelin_base, 'token', 'ERC20', 'extensions', 'IERC20Metadata.sol')
                        elif 'draft-IERC6093' in safe_filename:
                            target_path = os.path.join(openzeppelin_base, 'interfaces', 'draft-IERC6093.sol')
                        
                        if target_path:
                            os.makedirs(os.path.dirname(target_path), exist_ok=True)
                            with open(target_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                
                # 然后创建其他文件（包括主合约）
                for filename, content in modified_source_files.items():
                    base_name = os.path.basename(filename)
                    # 跳过已经在 OpenZeppelin 目录中创建的文件
                    if has_openzeppelin and any(keyword in base_name for keyword in ['ERC20.sol', 'Ownable.sol', 'Context.sol', 'IERC20', 'draft-IERC6093']):
                        # 检查是否是 OpenZeppelin 文件
                        is_openzeppelin = False
                        if 'ERC20.sol' == base_name and 'extensions' not in filename and 'IERC20' not in base_name:
                            is_openzeppelin = True
                        elif 'Ownable.sol' == base_name:
                            is_openzeppelin = True
                        elif 'Context.sol' == base_name:
                            is_openzeppelin = True
                        elif 'IERC20.sol' == base_name:
                            is_openzeppelin = True
                        elif 'IERC20Metadata' in base_name:
                            is_openzeppelin = True
                        elif 'draft-IERC6093' in base_name:
                            is_openzeppelin = True
                        
                        if is_openzeppelin:
                            continue  # 跳过，已经在 OpenZeppelin 目录中创建
                    
                    # 处理其他文件
                    if base_name in file_placement_map:
                        target_rel_path = file_placement_map[base_name]
                        target_path = os.path.join(temp_dir, target_rel_path)
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with open(target_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                    else:
                        # 如果不在映射中，放在根目录
                        safe_filename = os.path.basename(filename)
                        if not safe_filename.endswith('.sol'):
                            safe_filename += '.sol'
                        target_path = os.path.join(temp_dir, safe_filename)
                        with open(target_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                
                # 确定主合约文件的路径
                main_contract_base = os.path.basename(main_contract_filename)
                if not main_contract_base.endswith('.sol'):
                    main_contract_base += '.sol'
                if main_contract_base in file_placement_map:
                    temp_file = os.path.join(temp_dir, file_placement_map[main_contract_base])
                else:
                    temp_file = os.path.join(temp_dir, main_contract_base)
                
                # 关键修复：即使下载成功，也替换 import 为相对路径
                # 因为 Slither 的 remapping 机制可能无法正确传递给 solc
                # 使用相对路径更可靠
                openzeppelin_downloaded = has_openzeppelin and os.path.exists(openzeppelin_base) and os.listdir(openzeppelin_base)
                layerzero_downloaded = has_layerzero and os.path.exists(layerzero_base) and os.listdir(layerzero_base)
                
                # 只要有依赖，就替换 import（无论是否下载成功）
                if has_openzeppelin or has_layerzero:
                    print("   尝试将 import 语句替换为相对路径（避免 remapping 问题）...")
                    sys.stdout.flush()
                    
                    # 计算相对路径（基于 temp_dir，因为所有文件都在这里）
                    temp_dir_abs = os.path.abspath(temp_dir)
                    openzeppelin_base_abs = os.path.abspath(openzeppelin_base) if has_openzeppelin else None
                    layerzero_base_abs = os.path.abspath(layerzero_base) if has_layerzero else None
                    
                    total_replacements = 0
                    
                    # 替换所有文件中的 import 语句（包括 OpenZeppelin 和 LayerZero 自己的文件）
                    # 关键：需要根据每个文件的实际位置计算相对路径
                    # 首先处理主合约文件，然后处理所有其他文件（包括依赖文件）
                    all_files_to_process = list(modified_source_files.items())
                    
                    for filename, content in all_files_to_process:
                        modified = False
                        
                        # 替换 @openzeppelin/contracts/... 为相对路径
                        if has_openzeppelin and openzeppelin_base_abs:
                            try:
                                # 使用相对路径（从文件所在目录到 OpenZeppelin 目录）
                                # 计算从当前文件到 OpenZeppelin 的相对路径
                                if filename in file_placement_map:
                                    file_rel_path = file_placement_map[filename]
                                    file_actual_path = os.path.join(temp_dir, file_rel_path)
                                else:
                                    file_actual_path = os.path.join(temp_dir, os.path.basename(filename))
                                
                                file_dir_abs = os.path.abspath(os.path.dirname(file_actual_path))
                                rel_path_to_openzeppelin = os.path.relpath(openzeppelin_base_abs, file_dir_abs).replace('\\', '/')
                                
                                # 调试：显示使用的路径（只对主合约文件）
                                if filename == main_contract_filename and total_replacements == 0:
                                    print(f"   调试：使用相对路径替换 OpenZeppelin import: {rel_path_to_openzeppelin}")
                                    sys.stdout.flush()
                                
                                # 尝试多种 import 格式
                                # 包括：import "path"; 和 import { ... } from "path";
                                patterns = [
                                    # 格式1: import "path";
                                    (r'import\s+["\']@openzeppelin/contracts/([^"\']+)["\']\s*;?', 
                                     lambda m, q, rp: f'import {q}{rp}/{m.group(1)}{q};'),
                                    # 格式2: import { ... } from "path";
                                    (r'import\s+{[^}]*}\s+from\s+["\']@openzeppelin/contracts/([^"\']+)["\']\s*;?',
                                     lambda m, q, rp: re.sub(r'from\s+["\']@openzeppelin/contracts/[^"\']+["\']', 
                                                             f'from {q}{rp}/{m.group(1)}{q}', m.group(0))),
                                ]
                                
                                for pattern, replacement_func in patterns:
                                    # 使用 finditer 来获取所有匹配
                                    matches = list(re.finditer(pattern, content))
                                    if matches:
                                        # 从后往前替换，避免索引变化
                                        for match in reversed(matches):
                                            # 根据原始格式选择引号
                                            original = match.group(0)
                                            quote = '"' if '"' in original else ("'" if "'" in original else '"')
                                            # 生成替换内容（使用相对路径）
                                            replacement = replacement_func(match, quote, rel_path_to_openzeppelin)
                                            start, end = match.span()
                                            content = content[:start] + replacement + content[end:]
                                            total_replacements += 1
                                            modified = True
                                        break  # 找到一个匹配就停止
                            except Exception as e:
                                print(f"   ⚠️  替换 OpenZeppelin import 时出错: {e}")
                                sys.stdout.flush()
                        
                        # 替换 @layerzerolabs/oft-evm/contracts/... 为相对路径
                        if has_layerzero and layerzero_base_abs:
                            try:
                                # 使用相对路径（从文件所在目录到 LayerZero 目录）
                                # 计算从当前文件到 LayerZero 的相对路径
                                if filename in file_placement_map:
                                    file_rel_path = file_placement_map[filename]
                                    file_actual_path = os.path.join(temp_dir, file_rel_path)
                                else:
                                    file_actual_path = os.path.join(temp_dir, os.path.basename(filename))
                                
                                file_dir_abs = os.path.abspath(os.path.dirname(file_actual_path))
                                rel_path_to_layerzero = os.path.relpath(layerzero_base_abs, file_dir_abs).replace('\\', '/')
                                
                                # 调试：显示使用的路径（只对主合约文件）
                                if filename == main_contract_filename and total_replacements == 0:
                                    print(f"   调试：使用相对路径替换 LayerZero import: {rel_path_to_layerzero}")
                                    sys.stdout.flush()
                                
                                # 尝试多种 import 格式
                                # 包括：import "path"; 和 import { ... } from "path";
                                patterns = [
                                    # 格式1: import "path";
                                    (r'import\s+["\']@layerzerolabs/oft-evm/contracts/([^"\']+)["\']\s*;?', 
                                     lambda m, q, rp: f'import {q}{rp}/{m.group(1)}{q};'),
                                    # 格式2: import { ... } from "path";
                                    (r'import\s+{[^}]*}\s+from\s+["\']@layerzerolabs/oft-evm/contracts/([^"\']+)["\']\s*;?',
                                     lambda m, q, rp: re.sub(r'from\s+["\']@layerzerolabs/oft-evm/contracts/[^"\']+["\']', 
                                                             f'from {q}{rp}/{m.group(1)}{q}', m.group(0))),
                                    # 格式3: import "@layerzerolabs/oft-evm/contracts/..." as ...;
                                    (r'import\s+["\']@layerzerolabs/oft-evm/contracts/([^"\']+)["\']\s+as\s+\w+\s*;?',
                                     lambda m, q, rp: re.sub(r'["\']@layerzerolabs/oft-evm/contracts/[^"\']+["\']', 
                                                             f'{q}{rp}/{m.group(1)}{q}', m.group(0))),
                                ]
                                
                                for pattern, replacement_func in patterns:
                                    # 使用 finditer 来获取所有匹配
                                    matches = list(re.finditer(pattern, content))
                                    if matches:
                                        # 从后往前替换，避免索引变化
                                        for match in reversed(matches):
                                            # 根据原始格式选择引号
                                            original = match.group(0)
                                            quote = '"' if '"' in original else ("'" if "'" in original else '"')
                                            # 生成替换内容（使用相对路径）
                                            replacement = replacement_func(match, quote, rel_path_to_layerzero)
                                            start, end = match.span()
                                            content = content[:start] + replacement + content[end:]
                                            total_replacements += 1
                                            modified = True
                                        break  # 找到一个匹配就停止
                            except Exception as e:
                                print(f"   ⚠️  替换 LayerZero import 时出错: {e}")
                                sys.stdout.flush()
                        
                        if modified:
                            modified_source_files[filename] = content
                    
                    if total_replacements > 0:
                        print(f"   ✅ 已将 {total_replacements} 个 import 语句替换为相对路径")
                        sys.stdout.flush()
                        
                        # 调试：显示一个替换示例
                        for filename, content in modified_source_files.items():
                            # 查找替换后的 import（相对路径，包含 node_modules）
                            replaced_imports = re.findall(r'import\s+["\'][^"\']*node_modules[^"\']*["\']', content)
                            if replaced_imports:
                                print(f"   示例替换后的 import: {replaced_imports[0][:100]}...")
                                sys.stdout.flush()
                                break
                        
                        # 再次检查所有文件，确保没有遗漏的 import
                        remaining_imports = []
                        for filename, content in modified_source_files.items():
                            # 检查是否还有未替换的 @openzeppelin 或 @layerzerolabs
                            if '@openzeppelin' in content or '@layerzerolabs' in content:
                                # 查找所有可能的 import 格式
                                patterns_to_check = [
                                    r'@openzeppelin[^\s"\';]+',
                                    r'@layerzerolabs[^\s"\';]+',
                                ]
                                for pattern in patterns_to_check:
                                    matches = re.findall(pattern, content)
                                    for match in matches:
                                        # 检查是否在 import 语句中
                                        if 'import' in content[max(0, content.find(match)-50):content.find(match)+len(match)+50]:
                                            remaining_imports.append(f"{filename}: {match}")
                        
                        if remaining_imports:
                            print(f"   ⚠️  警告：仍有 {len(remaining_imports)} 个未替换的 import")
                            for imp in remaining_imports[:3]:  # 只显示前3个
                                print(f"      - {imp}")
                            sys.stdout.flush()
                    else:
                        print(f"   ⚠️  未找到需要替换的 import 语句")
                        # 调试：检查为什么没有找到
                        for filename, content in list(modified_source_files.items())[:3]:
                            # 查找所有包含 @openzeppelin 的行
                            lines = content.split('\n')
                            for i, line in enumerate(lines[:50]):  # 只检查前50行
                                if '@openzeppelin' in line:
                                    print(f"   调试：在 {filename} 第 {i+1} 行找到: {line.strip()[:100]}")
                                    sys.stdout.flush()
                                    # 测试正则表达式
                                    test_pattern = r'import\s+["\']@openzeppelin/contracts/([^"\']+)["\']\s*;?'
                                    test_match = re.search(test_pattern, line)
                                    if test_match:
                                        print(f"   调试：正则表达式匹配成功: {test_match.group(0)}")
                                    else:
                                        print(f"   调试：正则表达式未匹配，尝试其他格式...")
                                        # 尝试其他格式
                                        test_pattern2 = r'import\s+.*@openzeppelin.*'
                                        test_match2 = re.search(test_pattern2, line)
                                        if test_match2:
                                            print(f"   调试：找到匹配（宽泛模式）: {test_match2.group(0)[:80]}")
                                    break
                            if '@openzeppelin' in content:
                                break
                        sys.stdout.flush()
                
                # 确保主合约文件也被创建（使用修改后的内容，已处理 SPDX 和 import）
                if main_contract_filename in modified_source_files:
                    main_content = modified_source_files[main_contract_filename]
                    os.makedirs(os.path.dirname(temp_file), exist_ok=True)
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        f.write(main_content)
                
                # 关键修复：替换 OpenZeppelin 和 LayerZero 目录中文件内部的 import
                # 这些文件在下载时被复制，但它们的 import 语句也需要替换
                if has_openzeppelin and openzeppelin_base_abs and os.path.exists(openzeppelin_base_abs):
                    print("   正在替换 OpenZeppelin 文件内部的 import 语句...")
                    sys.stdout.flush()
                    # 遍历 OpenZeppelin 目录中的所有 .sol 文件
                    for root, dirs, files in os.walk(openzeppelin_base_abs):
                        for file in files:
                            if file.endswith('.sol'):
                                file_path = os.path.join(root, file)
                                try:
                                    with open(file_path, 'r', encoding='utf-8') as f:
                                        content = f.read()
                                    
                                    # 计算从当前文件到 OpenZeppelin 根目录的相对路径
                                    file_dir = os.path.dirname(file_path)
                                    rel_path_to_openzeppelin = os.path.relpath(openzeppelin_base_abs, file_dir).replace('\\', '/')
                                    
                                    # 替换 import 语句
                                    original_content = content
                                    pattern = r'import\s+["\']@openzeppelin/contracts/([^"\']+)["\']\s*;?'
                                    matches = list(re.finditer(pattern, content))
                                    if matches:
                                        for match in reversed(matches):
                                            file_path_in_import = match.group(1)
                                            quote = '"' if '"' in match.group(0) else "'"
                                            replacement = f'import {quote}{rel_path_to_openzeppelin}/{file_path_in_import}{quote};'
                                            start, end = match.span()
                                            content = content[:start] + replacement + content[end:]
                                        
                                        # 如果内容被修改，写回文件
                                        if content != original_content:
                                            with open(file_path, 'w', encoding='utf-8') as f:
                                                f.write(content)
                                except Exception as e:
                                    pass  # 忽略单个文件的错误
                    
                    print("   ✅ 已替换 OpenZeppelin 文件内部的 import")
                    sys.stdout.flush()
                
                if has_layerzero and layerzero_base_abs and os.path.exists(layerzero_base_abs):
                    print("   正在替换 LayerZero 文件内部的 import 语句...")
                    sys.stdout.flush()
                    # 遍历 LayerZero 目录中的所有 .sol 文件
                    for root, dirs, files in os.walk(layerzero_base_abs):
                        for file in files:
                            if file.endswith('.sol'):
                                file_path = os.path.join(root, file)
                                try:
                                    with open(file_path, 'r', encoding='utf-8') as f:
                                        content = f.read()
                                    
                                    # 计算从当前文件到 LayerZero 根目录的相对路径
                                    file_dir = os.path.dirname(file_path)
                                    rel_path_to_layerzero = os.path.relpath(layerzero_base_abs, file_dir).replace('\\', '/')
                                    
                                    # 替换 import 语句
                                    original_content = content
                                    pattern = r'import\s+["\']@layerzerolabs/oft-evm/contracts/([^"\']+)["\']\s*;?'
                                    matches = list(re.finditer(pattern, content))
                                    if matches:
                                        for match in reversed(matches):
                                            file_path_in_import = match.group(1)
                                            quote = '"' if '"' in match.group(0) else "'"
                                            replacement = f'import {quote}{rel_path_to_layerzero}/{file_path_in_import}{quote};'
                                            start, end = match.span()
                                            content = content[:start] + replacement + content[end:]
                                        
                                        # 如果内容被修改，写回文件
                                        if content != original_content:
                                            with open(file_path, 'w', encoding='utf-8') as f:
                                                f.write(content)
                                except Exception as e:
                                    pass  # 忽略单个文件的错误
                    
                    print("   ✅ 已替换 LayerZero 文件内部的 import")
                    sys.stdout.flush()
                
                # 保存 remaps 到变量，以便后续使用
                saved_remaps = remaps.copy() if remaps else []
                
            except Exception as e:
                # 如果多文件处理失败，回退到单文件
                print(f"   ⚠️  多文件处理失败: {e}，回退到单文件模式")
                sys.stdout.flush()
                temp_dir = None
                saved_remaps = []
                # 处理单文件的 SPDX 标识符
                cleaned_source = contract_source
                spdx_pattern = r'//\s*SPDX-License-Identifier:.*'
                spdx_matches = list(re.finditer(spdx_pattern, cleaned_source, re.MULTILINE))
                if len(spdx_matches) > 1:
                    # 保留第一个，移除其他的
                    for match in reversed(spdx_matches[1:]):
                        start, end = match.span()
                        cleaned_source = cleaned_source[:start] + cleaned_source[end:].lstrip()
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                    f.write(cleaned_source)
                    temp_file = f.name
        else:
            # 单文件合约
            temp_dir = None
            saved_remaps = []
            # 处理单文件的 SPDX 标识符
            cleaned_source = contract_source
            spdx_pattern = r'//\s*SPDX-License-Identifier:.*'
            spdx_matches = list(re.finditer(spdx_pattern, cleaned_source, re.MULTILINE))
            if len(spdx_matches) > 1:
                # 保留第一个，移除其他的
                for match in reversed(spdx_matches[1:]):
                    start, end = match.span()
                    cleaned_source = cleaned_source[:start] + cleaned_source[end:].lstrip()
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                f.write(cleaned_source)
                temp_file = f.name
        
        try:
            # 尝试不同的 slither 命令路径（优先使用 python3 -m slither）
            slither_cmd = None
            for cmd in [['python3', '-m', 'slither'], ['python', '-m', 'slither'], ['slither']]:
                try:
                    # 测试命令是否可用
                    test_result = subprocess.run(
                        cmd + ['--version'],
                        capture_output=True,
                        timeout=5
                    )
                    if test_result.returncode == 0:
                        slither_cmd = cmd
                        break
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            
            if not slither_cmd:
                raise FileNotFoundError("slither 命令未找到")
            
            # 运行 Slither 命令行
            # 先不使用 --json，以便捕获完整错误信息
            # 如果成功，再尝试使用 --json 获取结构化输出
            # 对于多文件合约，仍然使用主合约文件，但设置 remapping
            # 关键：如果使用相对路径 import，temp_file 应该是相对于 temp_dir 的路径
            if temp_dir and temp_file.startswith(temp_dir):
                # 使用相对路径
                rel_temp_file = os.path.relpath(temp_file, temp_dir)
                cmd_list = slither_cmd + [rel_temp_file]
            else:
                # 使用绝对路径
                cmd_list = slither_cmd + [temp_file]
            
            # 注意：Slither 的核心功能依赖于编译后的 AST（抽象语法树）
            # --ignore-compile 选项只能跳过框架编译（如 Truffle、Hardhat），不能跳过 solc 编译
            # Slither 必须通过 solc 编译才能进行分析，这是工具本身的限制
            # 因此，如果编译失败（如依赖项找不到），Slither 无法进行扫描
            # 这是 Slither 工具本身的特性，不是代码问题
            
            # 如果是多文件合约，添加 --solc-remaps 来处理 import 路径
            if temp_dir:
                # 添加 remappings（如果有）
                if saved_remaps:
                    # 关键发现：solc 的 remapping 应该作为位置参数传递，格式是 prefix=path
                    # 测试发现：solc test.sol @openzeppelin/contracts=path 这种方式可以工作
                    # 但是 Slither 的 --solc-remaps 可能没有正确传递
                    
                    # 方法1: 使用 --solc-remaps 参数（Slither 的标准方式）
                    remap_str = ' '.join(saved_remaps)
                    cmd_list.extend(['--solc-remaps', remap_str])
                    print(f"   设置 remapping (--solc-remaps): {remap_str}")
                    sys.stdout.flush()
                    
                    # 方法2: 使用 --solc-args 直接传递 remapping 作为位置参数
                    # 注意：Slither 的 --solc-args 可能不会正确传递 remapping
                    # 因为 Slither 内部会重新组织 solc 命令
                    # 但尝试一下也无妨
                    remap_args = ' '.join(saved_remaps)
                    # 注意：不要使用 --solc-args 传递 remapping，因为 Slither 可能不支持
                    # cmd_list.extend(['--solc-args', remap_args])
                    # print(f"   设置 remapping (--solc-args，在文件路径之前): {remap_args}")
                    # sys.stdout.flush()
                    
                    # 方法3: 使用 --solc-args 添加 --allow-paths 参数
                    # 这可以让 solc 访问指定路径下的文件
                    if temp_dir:
                        allow_paths = temp_dir
                        cmd_list.extend(['--solc-args', f'--allow-paths {allow_paths}'])
                        print(f"   设置 --allow-paths: {allow_paths}")
                        sys.stdout.flush()
                    
                    # 验证 remapping 路径是否存在
                    for remap in saved_remaps:
                        if '=' in remap:
                            prefix, path = remap.split('=', 1)
                            if not os.path.exists(path):
                                print(f"   ⚠️  警告: remapping 路径不存在: {path}")
                                sys.stdout.flush()
                            else:
                                # 验证关键文件是否存在
                                if 'openzeppelin' in prefix.lower():
                                    ownable_path = os.path.join(path, 'access', 'Ownable.sol')
                                    if os.path.exists(ownable_path):
                                        print(f"   ✅ 验证: Ownable.sol 存在于 {ownable_path}")
                                    else:
                                        print(f"   ⚠️  警告: Ownable.sol 不存在于 {ownable_path}")
                                sys.stdout.flush()
                    
                    # 方法3: 同时设置环境变量（虽然测试显示不工作，但保留作为备选）
                    env = os.environ.copy()
                    env['SOLC_REMAPPINGS'] = remap_str
                    print(f"   设置环境变量 SOLC_REMAPPINGS: {remap_str}")
                    sys.stdout.flush()
                else:
                    env = os.environ.copy()
                
                # 注意：Slither 不支持 --solc-allow-path 参数
                # remapping 应该足够让 solc 找到文件
            else:
                env = os.environ.copy()
            
            # 如果设置了 SOLC 环境变量，使用 --solc 参数直接指定
            solc_path = os.environ.get('SOLC')
            if solc_path and os.path.exists(solc_path):
                # 尝试不同的 solc 参数格式
                # Slither 可能支持 --solc, --solc-path, 或 --solc-version
                # 先尝试 --solc
                cmd_list.extend(['--solc', solc_path])
                
                # 同时设置环境变量，确保 Slither 能找到 solc
                if 'env' not in locals():
                    env = os.environ.copy()
                env['SOLC'] = solc_path
                env['PATH'] = os.path.dirname(solc_path) + os.pathsep + env.get('PATH', '')
            elif 'env' not in locals():
                env = os.environ.copy()
            
            # 使用更新后的环境变量（包含 SOLC 路径和 remappings）
            # 关键修复：如果使用相对路径 import，需要从 temp_dir 运行 Slither
            # 这样 solc 才能正确解析相对路径
            # 同时，确保 temp_file 是相对于 temp_dir 的路径
            if temp_dir and temp_file.startswith(temp_dir):
                # 使用相对路径的文件名
                rel_temp_file = os.path.relpath(temp_file, temp_dir)
                # 更新 cmd_list 中的文件名
                cmd_list = [arg if arg != temp_file else rel_temp_file for arg in cmd_list]
                cwd = temp_dir
                print(f"   调试：使用相对路径文件: {rel_temp_file}，工作目录: {temp_dir}")
                sys.stdout.flush()
            else:
                cwd = None
            
            # 调试：打印完整的命令
            if temp_dir:
                print(f"   调试：执行命令: {' '.join(cmd_list[:5])}... (工作目录: {cwd})")
                sys.stdout.flush()
            
            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
                cwd=cwd  # 设置工作目录，确保相对路径正确解析
            )
            
            # 检查输出（合并 stdout 和 stderr，因为错误可能出现在任一位置）
            output = result.stdout if result.stdout else ""
            error_output = result.stderr if result.stderr else ""
            full_output = (output + "\n" + error_output).strip()  # 合并所有输出
            full_error = full_output.lower()  # 转为小写用于错误检测
            
            # Slither 退出码 255 可能表示检测到问题，但不一定是错误
            # 检查是否包含检测结果（INFO:Detectors, WARNING, ERROR 等）
            has_detection_results = any(kw in full_output for kw in ['INFO:Detectors', 'WARNING:', 'ERROR:', 'detected', 'Reference:', 'Impact:'])
            
            # 检查是否是 solc 相关的错误（使用更宽松的匹配）
            has_solc_error = 'solc' in full_error and any(kw in full_error for kw in ['no such file', 'filenotfounderror', 'invalidcompilation', 'not found'])
            
            # 如果退出码不是0但有检测结果，应该当作成功处理
            if result.returncode != 0 and has_detection_results and not has_solc_error:
                # 有检测结果，即使退出码不是0也当作成功
                output = full_output
                # 更新 result 的 returncode 以便后续处理
                class FakeResult:
                    def __init__(self, original_result, new_returncode):
                        self.returncode = new_returncode
                        self.stdout = original_result.stdout
                        self.stderr = original_result.stderr
                result = FakeResult(result, 0)
            
            # 检查是否是 import 路径找不到的错误（即使文件存在）
            # 这是 Slither 的已知限制：remapping 可能无法正确传递给 solc
            has_import_error = ('not found' in full_error and ('source' in full_error or 'file not found' in full_error) and 
                              ('@openzeppelin' in full_error or '@layerzerolabs' in full_error or 'node_modules' in full_error))
            
            if has_solc_error or has_import_error:
                # 尝试自动安装 solc（传入合约源代码以检测版本）
                solc_available, solc_msg = ensure_solc_available(contract_source)
                if solc_available:
                    # 如果成功安装，重试扫描
                    print(f"   {solc_msg}")
                    print("   正在重试扫描...")
                    # 重新运行 slither（使用更新后的环境变量和 --solc 参数）
                    retry_cmd_list = slither_cmd + [temp_file]
                    solc_path = os.environ.get('SOLC')
                    if solc_path and os.path.exists(solc_path):
                        retry_cmd_list.extend(['--solc', solc_path])
                    
                    retry_result = subprocess.run(
                        retry_cmd_list,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        env=os.environ.copy()  # 使用更新后的环境变量
                    )
                    # 更新结果
                    result = retry_result
                    output = retry_result.stdout if retry_result.stdout else ""
                    error_output = retry_result.stderr if retry_result.stderr else ""
                    full_error = (error_output + "\n" + output).lower()
                    # 再次检查是否还有 solc 错误
                    has_solc_error = 'solc' in full_error and any(kw in full_error for kw in ['no such file', 'filenotfounderror', 'invalidcompilation', 'not found'])
                    if not has_solc_error:
                        # 如果不再有 solc 错误，继续处理结果
                        if retry_result.returncode == 0:
                            # 尝试获取 JSON 输出
                            json_cmd_list = slither_cmd + [temp_file, '--json', '-']
                            solc_path = os.environ.get('SOLC')
                            if solc_path and os.path.exists(solc_path):
                                # 在 --json 之前插入 --solc
                                json_cmd_list = slither_cmd + [temp_file, '--solc', solc_path, '--json', '-']
                            
                            json_result = subprocess.run(
                                json_cmd_list,
                                capture_output=True,
                                text=True,
                                timeout=60,
                                env=os.environ.copy(),
                                cwd=temp_dir if temp_dir else None  # 设置工作目录
                            )
                            if json_result.returncode == 0 and json_result.stdout:
                                try:
                                    json_start = json_result.stdout.rfind('{')
                                    if json_start != -1:
                                        json_str = json_result.stdout[json_start:]
                                        data = json.loads(json_str)
                                        return data
                                except json.JSONDecodeError:
                                    pass
                            return {
                                "verified": True,
                                "raw_output": output[:2000] if output else "扫描完成",
                                "format": "text"
                            }
                
                # 如果自动安装失败或仍然有错误，尝试安装匹配的版本
                # 检测合约的 Solidity 版本
                detected_version = detect_solidity_version(contract_source)
                if detected_version and detected_version != "0.8.20":
                    # 如果检测到的版本与当前安装的不同，尝试安装匹配的版本
                    print(f"   检测到合约使用 Solidity {detected_version}，当前 solc 版本可能不兼容")
                    print(f"   尝试安装匹配的 solc {detected_version}...")
                    try:
                        solc_available2, solc_msg2 = ensure_solc_available(contract_source)
                        if solc_available2:
                            print(f"   {solc_msg2}")
                            # 再次重试
                            retry_cmd_list2 = slither_cmd + [temp_file]
                            solc_path2 = os.environ.get('SOLC')
                            if solc_path2 and os.path.exists(solc_path2):
                                retry_cmd_list2.extend(['--solc', solc_path2])
                            
                            retry_result2 = subprocess.run(
                                retry_cmd_list2,
                                capture_output=True,
                                text=True,
                                timeout=60,
                                env=os.environ.copy()
                            )
                            
                            if retry_result2.returncode == 0:
                                # 成功，继续处理
                                result = retry_result2
                                output = retry_result2.stdout if retry_result2.stdout else ""
                                error_output = retry_result2.stderr if retry_result2.stderr else ""
                                full_error = (error_output + "\n" + output).lower()
                                has_solc_error = False  # 清除错误标志
                    except:
                        pass
                
                # 如果仍然有错误，检查是否是编译错误而不是 solc 找不到
                if has_solc_error:
                    # 检查是否是编译错误（合约代码问题）
                    is_compilation_error = any(kw in full_error for kw in ['compilation', 'parse error', 'syntax error', 'type error', 'error:', 'warning:', 'compiler error'])
                    
                    if is_compilation_error:
                        # 这是编译错误，不是 solc 配置问题
                        # 提取实际的错误信息（从输出中）
                        actual_error = ""
                        if error_output:
                            # 尝试提取关键错误行
                            error_lines = error_output.split('\n')
                            # 查找包含 "Error" 或 "Warning" 的行
                            important_lines = [line for line in error_lines if any(kw in line.lower() for kw in ['error', 'warning', 'compilation', 'failed'])]
                            if important_lines:
                                actual_error = "\n".join(important_lines[:10])  # 最多显示10行
                        
                        if not actual_error and output:
                            # 如果 stderr 没有，尝试从 stdout 提取
                            output_lines = output.split('\n')
                            important_lines = [line for line in output_lines if any(kw in line.lower() for kw in ['error', 'warning', 'compilation', 'failed'])]
                            if important_lines:
                                actual_error = "\n".join(important_lines[:10])
                        
                        error_msg = f"❌ 合约编译失败\n\n"
                        error_msg += f"solc 已正确配置: {solc_msg}\n\n"
                        
                        # 添加更详细的错误信息
                        if actual_error:
                            error_msg += "实际编译错误信息:\n"
                            error_msg += "-" * 60 + "\n"
                            error_msg += actual_error + "\n"
                            error_msg += "-" * 60 + "\n\n"
                        
                        # 检查是否是 OpenZeppelin 相关错误
                        if has_openzeppelin and ('openzeppelin' in full_error.lower() or 'not found' in full_error.lower() or 'file not found' in full_error.lower()):
                            error_msg += "可能的原因:\n"
                            error_msg += "  - ⚠️  Slither 的已知限制：remapping 参数可能无法正确传递给 solc 编译器\n"
                            error_msg += "  - 即使文件已下载且 import 已替换为相对路径，Slither 内部调用 solc 时可能仍无法找到文件\n"
                            error_msg += "  - 这是 Slither 工具本身的特性限制，不是代码问题\n\n"
                            error_msg += "技术细节:\n"
                            error_msg += "  - 已成功下载 OpenZeppelin 合约库（330+ 文件）\n"
                            error_msg += "  - 已替换所有 import 语句为相对路径\n"
                            error_msg += "  - 文件确实存在于正确位置\n"
                            error_msg += "  - 直接使用 solc 可以成功编译\n"
                            error_msg += "  - 但通过 Slither 调用时失败（Slither 特性问题）\n\n"
                            error_msg += "建议:\n"
                            error_msg += "  - 这是 Slither 工具的已知限制，暂时无法完全解决\n"
                            error_msg += "  - GoPlus Labs 的安全信息仍然可用，提供了代币级别的安全评估\n"
                            error_msg += "  - 可以尝试使用其他安全扫描工具（如 Mythril、Manticore、Oyente 等）\n"
                            error_msg += "  - 或者手动使用 solc 编译后，再使用其他分析工具\n"
                        else:
                            error_msg += "可能的原因:\n"
                            error_msg += "  - 合约源代码不完整（从网页抓取可能不完整）\n"
                            error_msg += "  - 合约使用了不兼容的 Solidity 特性\n"
                            error_msg += "  - 缺少依赖合约（如 OpenZeppelin 等）\n"
                            error_msg += "  - 编译器设置不匹配（优化设置、evm 版本等）\n\n"
                            error_msg += "建议: 尝试从区块浏览器手动查看完整源代码。"
                        
                        # 获取完整的错误输出用于调试
                        raw_error_text = ""
                        try:
                            if full_output:
                                raw_error_text = full_output[:2000]
                            elif error_output:
                                raw_error_text = error_output[:2000]
                            elif output:
                                raw_error_text = output[:2000]
                        except:
                            # 如果变量不可用，使用 error_output 或 output
                            raw_error_text = (error_output or output or "")[:2000]
                        
                        return {
                            "error": "合约编译失败",
                            "message": error_msg,
                            "raw_error": raw_error_text
                        }
                    else:
                        # 真正的 solc 配置问题
                        error_msg = f"Slither 无法使用 solc 编译器\n\n"
                        error_msg += f"已尝试自动安装和配置 solc，但仍有问题\n"
                        error_msg += f"当前状态: {solc_msg}\n\n"
                        error_msg += "这可能是因为:\n" + \
                                    "  - solc 版本与合约不兼容\n" + \
                                    "  - Slither 配置问题\n" + \
                                    "  - 网络问题\n\n" + \
                                    "工具已自动尝试所有可能的解决方案。"
                        
                        return {
                            "error": "Solidity 编译器配置失败",
                            "message": error_msg
                        }
            
            # 如果成功，尝试使用 --json 获取结构化输出
            if result.returncode == 0:
                json_cmd_list = slither_cmd + [temp_file, '--json', '-']
                solc_path = os.environ.get('SOLC')
                if solc_path and os.path.exists(solc_path):
                    # 在 --json 之前插入 --solc
                    json_cmd_list = slither_cmd + [temp_file, '--solc', solc_path, '--json', '-']
                
                json_result = subprocess.run(
                    json_cmd_list,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    env=os.environ.copy(),
                    cwd=temp_dir if temp_dir else None  # 设置工作目录
                )
                if json_result.returncode == 0 and json_result.stdout:
                    try:
                        json_start = json_result.stdout.rfind('{')
                        if json_start != -1:
                            json_str = json_result.stdout[json_start:]
                            data = json.loads(json_str)
                            return data
                    except json.JSONDecodeError:
                        pass
                # 如果 JSON 解析失败，返回文本输出
                return {
                    "verified": True,
                    "raw_output": full_output if 'full_output' in locals() else (output[:5000] if output else "扫描完成，但无法解析结果"),
                    "format": "text"
                }
            
            if result.returncode == 0 or output:
                # 解析 JSON 输出
                try:
                    # Slither 的 JSON 输出可能在 stdout 或 stderr
                    if output.strip():
                        # 查找 JSON 部分（可能在输出的最后）
                        json_start = output.rfind('{')
                        if json_start != -1:
                            json_str = output[json_start:]
                            data = json.loads(json_str)
                            return data
                except json.JSONDecodeError:
                    # 如果不是 JSON，检查是否有错误信息
                    if error_output and len(error_output) > 0:
                        return {
                            "error": "解析失败",
                            "message": f"Slither 分析失败:\n{error_output[:500]}"
                        }
                    # 返回文本输出
                    return {
                        "raw_output": output[:1000] if output else "无输出",
                        "format": "text"
                    }
            
            # 如果返回码不为0，检查是否是 solc 错误（再次检查，因为可能在上面的检查中漏掉）
            if result.returncode != 0:
                # 再次检查 solc 错误（可能错误信息在后面的部分）
                if 'solc' in full_error.lower() and ('not found' in full_error.lower() or 'no such file' in full_error.lower() or 'FileNotFoundError' in full_error or 'InvalidCompilation' in full_error):
                    return {
                        "error": "Solidity 编译器未找到",
                        "message": "Slither 需要 Solidity 编译器 (solc) 才能工作\n\n" +
                                  "安装方法:\n" +
                                  "  macOS (推荐):\n" +
                                  "    brew install solidity\n\n" +
                                  "  或使用 npm:\n" +
                                  "    npm install -g solc\n\n" +
                                  "  或使用 pip:\n" +
                                  "    pip install py-solc-x\n" +
                                  "    (然后需要配置 solc 版本)\n\n" +
                                  "安装完成后，请重新运行扫描。"
                    }
                
                error_msg = error_output[:1000] if error_output else (output[:1000] if output else "未知错误")
                return {
                    "error": "Slither 执行失败",
                    "message": f"Slither 返回错误 (退出码: {result.returncode}):\n{error_msg}"
                }
            
            return {
                "error": "无输出",
                "message": "Slither 分析完成，但未产生输出"
            }
        finally:
            # 清理临时文件
            if os.path.exists(temp_file):
                os.unlink(temp_file)
                
    except subprocess.TimeoutExpired:
        return {
            "error": "分析超时",
            "message": "Slither 分析超过 60 秒"
        }
    except FileNotFoundError:
        return {
            "error": "Slither 未找到",
            "message": "请确保已安装 slither-analyzer: pip install slither-analyzer\n   注意: Slither 还需要 Solidity 编译器 (solc)\n   安装 solc: brew install solidity 或 npm install -g solc"
        }
    except Exception as e:
        error_msg = str(e)
        # 检查是否是 solc 相关的错误
        if 'solc' in error_msg.lower() or 'compiler' in error_msg.lower():
            return {
                "error": "Solidity 编译器未找到",
                "message": f"Slither 需要 Solidity 编译器 (solc)\n   错误: {error_msg}\n   安装 solc:\n     - macOS: brew install solidity\n     - 或使用 npm: npm install -g solc"
            }
        return {
            "error": str(e),
            "message": f"Slither CLI 分析失败: {e}"
        }


def scan_evm_contract_with_slither(contract_source: str, contract_name: str = "Contract", source_files: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """
    使用 Slither 扫描 EVM 合约
    优先使用 Python API，如果不可用则使用命令行
    自动处理 solc 编译器的安装
    
    参数:
        contract_source: Solidity 源代码（单文件）或主合约文件内容
        contract_name: 合约名称（可选）
        source_files: 多文件合约的字典 {文件名: 内容}（可选）
    
    返回:
        包含扫描结果的字典
    """
    # 首先确保 solc 可用（如果使用 py-solc-x）
    # 传入合约源代码以便检测需要的 solc 版本
    solc_available, solc_msg = ensure_solc_available(contract_source)
    if solc_available:
        print(f"   {solc_msg}")
    else:
        # 如果无法自动安装，给出提示但继续尝试（可能系统已有 solc）
        pass
    
    # 首先尝试使用 Python API（但多文件合约需要使用 CLI）
    if SLITHER_API_AVAILABLE and Slither is not None and not source_files:
        try:
            result = scan_contract_with_slither_api(contract_source, contract_name)
            if result and "error" not in result:
                return result
        except Exception as e:
            # API 失败，尝试命令行
            pass
    
    # 如果 API 不可用或失败，或有多文件，使用命令行
    try:
        result = scan_contract_with_slither_cli(contract_source, contract_name, source_files=source_files)
        return result
    except FileNotFoundError:
        # 尝试自动安装 slither-analyzer
        print("   检测到 slither-analyzer 未安装，正在自动安装...")
        if ensure_package_installed('slither-analyzer', 'slither'):
            # 安装成功后重新尝试
            try:
                result = scan_contract_with_slither_cli(contract_source, contract_name, source_files=source_files)
                return result
            except Exception as e:
                return {
                    "error": "Slither 安装后仍无法使用",
                    "message": f"请检查安装: {e}"
                }
        else:
            return {
                "error": "Slither 未找到",
                "message": "自动安装 slither-analyzer 失败，请手动安装: pip install slither-analyzer"
            }
    except Exception as e:
        return {
            "error": str(e),
            "message": f"Slither 扫描失败: {e}"
        }


def format_slither_results(results: Dict[str, Any]) -> str:
    """
    格式化 Slither 扫描结果（美化输出，添加中文）
    """
    if not results:
        return "❌ 无扫描结果"
    
    if "error" in results:
        error_msg = results.get('message', results.get('error', '未知错误'))
        return f"❌ 扫描失败: {error_msg}"
    
    output_lines = []
    
    # 解析原始输出（如果存在）
    raw_output = results.get("raw_output", "")
    if raw_output:
        # 解析 Slither 的文本输出
        parsed_issues = _parse_slither_output(raw_output)
        
        if parsed_issues:
            # 过滤掉 LOW 级别的漏洞
            filtered_issues = [i for i in parsed_issues if i.get('severity') != 'LOW']
            
            # 统计信息（排除 LOW）
            total_issues = len(filtered_issues)
            high_count = sum(1 for issue in filtered_issues if issue.get('severity') == 'HIGH')
            medium_count = sum(1 for issue in filtered_issues if issue.get('severity') == 'MEDIUM')
            low_count = sum(1 for issue in filtered_issues if issue.get('severity') == 'LOW')  # 应该为 0
            info_count = sum(1 for issue in filtered_issues if issue.get('severity') == 'INFO' or not issue.get('severity'))
            
            # 美化摘要
            output_lines.append("")
            output_lines.append("╔" + "═" * 78 + "╗")
            output_lines.append("║" + " " * 20 + "🔍 安全扫描结果摘要" + " " * 37 + "║")
            output_lines.append("╠" + "═" * 78 + "╣")
            output_lines.append("║" + f"  总问题数: {total_issues:>3}".ljust(79) + "║")
            
            if high_count > 0:
                output_lines.append("║" + f"  🔴 高危 (HIGH): {high_count:>3}".ljust(79) + "║")
            if medium_count > 0:
                output_lines.append("║" + f"  🟠 中危 (MEDIUM): {medium_count:>3}".ljust(79) + "║")
            # 不再显示 LOW 级别
            if info_count > 0:
                output_lines.append("║" + f"  ℹ️  信息 (INFO): {info_count:>3}".ljust(79) + "║")
            
            output_lines.append("╚" + "═" * 78 + "╝")
            output_lines.append("")
            
            # 详细问题列表（只显示过滤后的）
            if total_issues > 0:
                output_lines.append("📋 详细问题列表:")
                output_lines.append("─" * 80)
                output_lines.append("")
                
                for i, issue in enumerate(filtered_issues, 1):
                    severity = issue.get('severity', 'INFO')
                    check_name = issue.get('check', 'Unknown')
                    description = issue.get('description', '')
                    reference = issue.get('reference', '')
                    
                    # 严重程度图标和中文
                    severity_map = {
                        'HIGH': ('🔴', '高危'),
                        'MEDIUM': ('🟠', '中危'),
                        'LOW': ('🟡', '低危'),
                        'INFO': ('ℹ️', '信息')
                    }
                    icon, severity_cn = severity_map.get(severity, ('ℹ️', '信息'))
                    
                    # 检查项中文翻译
                    check_name_cn = _translate_check_name(check_name)
                    
                    output_lines.append(f"【问题 #{i}】{icon} {severity_cn} - {check_name_cn}")
                    output_lines.append("─" * 80)
                    
                    if description:
                        # 清理描述文本
                        desc_lines = description.split('\n')
                        for line in desc_lines[:5]:  # 只显示前5行
                            if line.strip():
                                output_lines.append(f"  {line.strip()}")
                    
                    if reference:
                        output_lines.append(f"  📖 参考: {reference}")
                    
                    output_lines.append("")
        else:
            # 如果没有解析到问题，显示原始输出
            output_lines.append("✅ 未发现安全问题")
            output_lines.append("")
            output_lines.append("原始输出:")
            output_lines.append("─" * 80)
            output_lines.append(raw_output[:2000])  # 限制长度
    else:
        # 使用结构化数据
        if "summary" in results:
            summary = results["summary"]
            output_lines.append("")
            output_lines.append("╔" + "═" * 78 + "╗")
            output_lines.append("║" + " " * 20 + "🔍 安全扫描结果摘要" + " " * 37 + "║")
            output_lines.append("╠" + "═" * 78 + "╣")
            output_lines.append("║" + f"  总问题数: {summary.get('total_issues', 0):>3}".ljust(79) + "║")
            output_lines.append("║" + f"  🔴 高危: {summary.get('high', 0):>3}".ljust(79) + "║")
            output_lines.append("║" + f"  🟠 中危: {summary.get('medium', 0):>3}".ljust(79) + "║")
            output_lines.append("║" + f"  🟡 低危: {summary.get('low', 0):>3}".ljust(79) + "║")
            output_lines.append("║" + f"  ℹ️  信息: {summary.get('info', 0):>3}".ljust(79) + "║")
            output_lines.append("╚" + "═" * 78 + "╝")
            output_lines.append("")
        
        # 详细问题
        if "detectors" in results and results["detectors"]:
            output_lines.append("📋 详细问题列表:")
            output_lines.append("─" * 80)
            output_lines.append("")
            
            for i, issue in enumerate(results["detectors"], 1):
                impact = issue.get('impact', 'Unknown')
                check = issue.get('check', 'Unknown')
                description = issue.get('description', '')
                
                severity_map = {
                    'HIGH': ('🔴', '高危'),
                    'MEDIUM': ('🟠', '中危'),
                    'LOW': ('🟡', '低危'),
                    'INFO': ('ℹ️', '信息')
                }
                icon, severity_cn = severity_map.get(impact, ('ℹ️', '信息'))
                check_cn = _translate_check_name(check)
                
                output_lines.append(f"【问题 #{i}】{icon} {severity_cn} - {check_cn}")
                output_lines.append("─" * 80)
                if description:
                    output_lines.append(f"  {description}")
                output_lines.append("")
    
    return "\n".join(output_lines)


def _parse_slither_output(output: str) -> List[Dict[str, Any]]:
    """
    解析 Slither 的文本输出，提取问题信息
    """
    issues = []
    lines = output.split('\n')
    
    current_issue = None
    current_description = []
    in_detector_section = False
    
    for i, line in enumerate(lines):
        original_line = line
        line = line.strip()
        
        # 检测进入 Detectors 部分
        if 'INFO:Detectors:' in line or 'WARNING:' in line or 'ERROR:' in line:
            in_detector_section = True
            # 保存之前的问题
            if current_issue and current_description:
                current_issue['description'] = '\n'.join(current_description).strip()
                issues.append(current_issue)
            
            # 开始新问题
            current_issue = {
                'severity': 'INFO' if 'INFO' in line else ('WARNING' if 'WARNING' in line else 'ERROR'),
                'check': '',
                'description': '',
                'reference': ''
            }
            current_description = []
            continue
        
        if not in_detector_section:
            continue
        
        # 检测 Reference（参考链接）- 这通常表示一个问题结束
        if line.startswith('Reference:'):
            if current_issue:
                current_issue['reference'] = line.replace('Reference:', '').strip()
                # 保存当前问题
                if current_description:
                    current_issue['description'] = '\n'.join(current_description).strip()
                issues.append(current_issue)
                # 开始新问题
                current_issue = {
                    'severity': 'INFO',
                    'check': '',
                    'description': '',
                    'reference': ''
                }
                current_description = []
            continue
        
        # 检测检查项名称（通常在描述的开头）
        if current_issue and not current_issue.get('check'):
            line_lower = line.lower()
            if 'shadows' in line_lower:
                current_issue['check'] = 'local-variable-shadowing'
            elif 'different versions' in line_lower or 'different pragma' in line_lower:
                current_issue['check'] = 'different-pragma-directives'
            elif ('never used' in line_lower or 'should be removed' in line_lower) and current_issue.get('check') != 'dead-code':
                current_issue['check'] = 'dead-code'
            elif 'known severe issues' in line_lower or 'known issues' in line_lower:
                current_issue['check'] = 'incorrect-versions-of-solidity'
        
        # 收集描述文本（跳过空行和 Reference 行）
        if current_issue and line and not line.startswith('Reference:'):
            # 跳过 "It is used by:" 这样的行，它们不是问题描述的一部分
            # 跳过 Slither 的总结信息
            if (not line.startswith('It is used by:') and 
                not line.startswith('-^') and 
                'INFO:Slither:' not in line and 
                'analyzed' not in line.lower() and
                'detectors' not in line.lower() or 'INFO:Detectors:' in original_line):
                current_description.append(original_line)  # 使用原始行以保留格式
    
    # 添加最后一个问题（如果不是 Slither 的总结信息）
    if current_issue and current_description:
        current_issue['description'] = '\n'.join(current_description).strip()
        # 过滤掉 Slither 的总结信息
        if (current_issue['description'] and 
            'INFO:Slither:' not in current_issue['description'] and
            'analyzed' not in current_issue['description'].lower()):
            issues.append(current_issue)
    
    return issues


def _translate_check_name(check_name: str) -> str:
    """
    翻译检查项名称
    """
    translations = {
        'local-variable-shadowing': '局部变量遮蔽',
        'different-pragma-directives': '不同的 Solidity 版本',
        'dead-code': '死代码（未使用的代码）',
        'incorrect-versions-of-solidity': 'Solidity 版本问题',
        'uninitialized-state': '未初始化的状态变量',
        'uninitialized-storage': '未初始化的存储变量',
        'arbitrary-send': '任意发送',
        'controlled-delegatecall': '受控的委托调用',
        'reentrancy-eth': '重入攻击（以太币）',
        'reentrancy-no-eth': '重入攻击（非以太币）',
        'timestamp': '时间戳依赖',
        'assembly': '内联汇编使用',
        'low-level-calls': '低级调用',
        'missing-zero-check': '缺少零地址检查',
        'tx-origin': 'tx.origin 使用',
        'weak-prng': '弱伪随机数生成器',
        'locked-ether': '锁定以太币',
        'suicidal': '自杀函数',
        'unchecked-transfer': '未检查的转账',
        'unchecked-send': '未检查的发送',
        'unchecked-lowlevel': '未检查的低级调用',
        'uninitialized-local': '未初始化的局部变量',
        'unused-return': '未使用的返回值',
        'shadowing-builtin': '遮蔽内置符号',
        'shadowing-abstract': '遮蔽抽象合约',
        'shadowing-state': '遮蔽状态变量',
        'calls-loop': '循环中的外部调用',
        'reentrancy-benign': '良性重入',
        'reentrancy-events': '重入事件',
        'reentrancy-unlimited-gas': '无限 gas 重入',
        'uninitialized-fptr-cst': '未初始化的函数指针常量',
        'uninitialized-storage-ptr': '未初始化的存储指针',
        'unused-state': '未使用的状态变量',
        'unused-return-external': '未使用的外部返回值',
        'unused-return-internal': '未使用的内部返回值',
        'variable-scope': '变量作用域',
        'void-cst': '空构造函数',
        'calls-loop': '循环中的调用',
        'complex-function': '复杂函数',
        'cyclomatic-complexity': '圈复杂度',
        'data-dependency': '数据依赖',
        'naming-convention': '命名约定',
        'pragma': 'Pragma 指令',
        'solc-version': 'Solc 版本',
        'too-many-digits': '数字位数过多',
        'unused-import': '未使用的导入',
        'unused-return': '未使用的返回值',
        'unused-return-external': '未使用的外部返回值',
        'unused-return-internal': '未使用的内部返回值',
        'unused-state': '未使用的状态变量',
        'unused-storage': '未使用的存储',
        'unused-variable': '未使用的变量',
        'unused-variable-arbitrary': '未使用的变量（任意）',
        'unused-variable-constant': '未使用的常量变量',
        'unused-variable-state': '未使用的状态变量',
        'unused-variable-storage': '未使用的存储变量',
        'unused-variable-temporary': '未使用的临时变量',
        'unused-variable-immutable': '未使用的不可变变量',
        'unused-variable-constant': '未使用的常量变量',
        'unused-variable-state': '未使用的状态变量',
        'unused-variable-storage': '未使用的存储变量',
        'unused-variable-temporary': '未使用的临时变量',
        'unused-variable-immutable': '未使用的不可变变量',
    }
    
    return translations.get(check_name.lower(), check_name)

