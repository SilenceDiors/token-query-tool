# 通用多链代币查询工具

一个支持多链代币信息查询和安全扫描的命令行工具。

## 支持的区块链

- **EVM 兼容链**：
  - Ethereum
  - BSC (Binance Smart Chain)
  - Polygon
  - Arbitrum
  - Optimism
  - Avalanche

- **其他链**：
  - Sui
  - Solana

## 安装

```bash
pip install -r requirements.txt
```

## 使用方法

### 命令行方式

#### 基本用法

```bash
# 显示代币基础信息
python3 main.py --info <代币地址> [--chain <链类型>]

# 生成代币代码压缩包
python3 main.py --code <合约地址> [--chain <链类型>]

# 安全扫描
python3 main.py --scan <代币地址> [--chain <链类型>]

# 生成LLM提示词
python3 main.py --llm <代币地址> [--chain <链类型>]

# 显示帮助信息
python3 main.py --help
```

#### 命令行选项

- `--info, -i`: 显示代币基础信息（不包含代码）
- `--code, -c`: 生成代币代码压缩包（EVM和Sui，不包括Solana）
- `--scan, -s`: 显示安全扫描信息
  - ETH: 模式匹配扫描结果 + GoPlus
  - SUI: Sui扫描脚本结果 + GoPlus
  - Solana: GoPlus结果
- `--llm, -l`: 生成LLM提示词（收集所有信息并生成文档提示词）
- `--chain, -C <链>`: 指定链类型（可选）
  - 支持的链: ethereum, bsc, polygon, arbitrum, optimism, avalanche, sui, solana
  - 如果不指定，EVM地址会自动尝试所有EVM链
- `--help, -h`: 显示帮助信息

### 使用示例

#### 1. 查询代币基础信息

```bash
# 自动检测链类型
python3 main.py --info 0xdAC17F958D2ee523a2206206994597C13D831ec7

# 指定链类型
python3 main.py --info 0x55d398326f99059fF775485246999027B3197955 --chain bsc

# Sui
python3 main.py --info 0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb

# Solana
python3 main.py --info EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v --chain solana
```

#### 2. 生成代码压缩包

```bash
# Ethereum
python3 main.py --code 0xdAC17F958D2ee523a2206206994597C13D831ec7

# BSC
python3 main.py --code 0x55d398326f99059fF775485246999027B3197955 --chain bsc

# Sui
python3 main.py --code 0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb
```

#### 3. 安全扫描

```bash
# Ethereum (模式匹配扫描 + GoPlus)
python3 main.py --scan 0xdAC17F958D2ee523a2206206994597C13D831ec7

# BSC
python3 main.py --scan 0x40b8129B786D766267A7a118cF8C07E31CDB6Fde --chain bsc

# Sui (Sui扫描 + GoPlus)
python3 main.py --scan 0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb

# Solana (GoPlus)
python3 main.py --scan EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v --chain solana
```

#### 4. 生成LLM提示词

```bash
# 收集所有信息并生成LLM提示词
python3 main.py --llm 0xdAC17F958D2ee523a2206206994597C13D831ec7

# 指定链类型
python3 main.py --llm 0x40b8129B786D766267A7a118cF8C07E31CDB6Fde --chain bsc
```

### 作为 Python 模块使用

```python
from token_query.cli import query_token_info_only, export_code_package, scan_token_security

# 查询代币信息
query_token_info_only("0x...", chain="ethereum")

# 导出代码
export_code_package("0x...", chain="ethereum")

# 安全扫描
scan_token_security("0x...", chain="ethereum")
```

## 功能特性

- **自动检测链类型**：根据地址格式自动识别链类型
- **多链支持**：支持EVM、Sui、Solana等多种区块链
- **代码获取**：
  - EVM链：直接从网页爬取已验证的合约源代码（无需API key）
  - Sui：通过RPC直接获取Move模块源代码
  - Solana：获取程序账户数据（BPF字节码）
- **安全扫描**：
  - EVM链：模式匹配扫描 + GoPlus Labs安全信息
  - Sui：Move代码安全扫描 + GoPlus Labs安全信息
  - Solana：GoPlus Labs安全信息
- **LLM提示词生成**：收集所有信息并生成专业的LLM提示词

## 项目结构

```
token-query-tool/
├── main.py                    # 主入口文件
├── requirements.txt           # 依赖列表
├── README.md                  # 项目说明
└── token_query/               # 核心代码目录
    ├── __init__.py
    ├── cli.py                 # 命令行接口
    ├── config.py              # 配置文件
    ├── chains/                # 链相关代码
    │   ├── evm.py
    │   ├── solana.py
    │   └── sui.py
    ├── code/                  # 代码获取模块
    │   ├── evm_code.py
    │   ├── solana_code.py
    │   └── sui_code.py
    ├── security/              # 安全扫描模块
    │   ├── goplus_scanner.py
    │   ├── pattern_scanner.py
    │   └── sui_scanner.py
    └── utils/                  # 工具函数
        ├── detection.py
        └── formatters.py
```

## 注意事项

- 代码获取功能**无需API key**，直接从网页或RPC获取
- EVM链会自动尝试所有支持的链（如果未指定）
- 安全扫描使用模式匹配，无需编译，无需外部依赖
- 生成的代码压缩包和LLM提示词会保存在当前目录
