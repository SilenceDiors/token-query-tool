"""
配置模块
包含 RPC 端点、链类型等配置信息
"""
import os

# RPC 端点配置
RPC_ENDPOINTS = {
    "ethereum": "https://eth.llamarpc.com",
    "bsc": "https://bsc.llamarpc.com",
    "polygon": "https://polygon.llamarpc.com",
    "arbitrum": "https://arbitrum.llamarpc.com",
    "optimism": "https://optimism.llamarpc.com",
    "avalanche": "https://avalanche.public-rpc.com",
    "sui": "https://fullnode.mainnet.sui.io:443",
    "solana": "https://api.mainnet-beta.solana.com",
}

# EVM兼容链列表
EVM_CHAINS = ["ethereum", "bsc", "polygon", "arbitrum", "optimism", "avalanche"]

# 标准ERC20 ABI（只需要name, symbol, decimals, totalSupply）
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    }
]

def get_supported_chains():
    """
    获取支持的链类型列表
    返回: dict，包含所有支持的链信息
    """
    return {
        "all_chains": list(RPC_ENDPOINTS.keys()),
        "evm_chains": EVM_CHAINS,
        "sui": ["sui"],
        "solana": ["solana"],
        "chain_info": {
            "ethereum": {"name": "Ethereum", "type": "EVM", "rpc": RPC_ENDPOINTS["ethereum"]},
            "bsc": {"name": "BSC (Binance Smart Chain)", "type": "EVM", "rpc": RPC_ENDPOINTS["bsc"]},
            "polygon": {"name": "Polygon", "type": "EVM", "rpc": RPC_ENDPOINTS["polygon"]},
            "arbitrum": {"name": "Arbitrum", "type": "EVM", "rpc": RPC_ENDPOINTS["arbitrum"]},
            "optimism": {"name": "Optimism", "type": "EVM", "rpc": RPC_ENDPOINTS["optimism"]},
            "avalanche": {"name": "Avalanche", "type": "EVM", "rpc": RPC_ENDPOINTS["avalanche"]},
            "sui": {"name": "Sui", "type": "Move", "rpc": RPC_ENDPOINTS["sui"]},
            "solana": {"name": "Solana", "type": "Solana", "rpc": RPC_ENDPOINTS["solana"]},
        }
    }

def get_chain_code_visibility():
    """
    获取各链代币合约代码的可查询性信息
    返回: dict，说明哪些链可以查询到代币源代码
    """
    return {
        "can_query_source_code": {
            # EVM链：如果合约验证了源代码，可以在区块浏览器查看
            "ethereum": {
                "can_query": True,
                "method": "通过区块浏览器（Etherscan）查看已验证的合约源代码",
                "explorer": "https://etherscan.io/address/{address}#code",
                "note": "需要合约部署者验证源代码才能查看",
                "rpc_method": "eth_getCode (只能获取字节码，不是源代码)"
            },
            "bsc": {
                "can_query": True,
                "method": "通过区块浏览器（BSCScan）查看已验证的合约源代码",
                "explorer": "https://bscscan.com/address/{address}#code",
                "note": "需要合约部署者验证源代码才能查看",
                "rpc_method": "eth_getCode (只能获取字节码，不是源代码)"
            },
            "polygon": {
                "can_query": True,
                "method": "通过区块浏览器（PolygonScan）查看已验证的合约源代码",
                "explorer": "https://polygonscan.com/address/{address}#code",
                "note": "需要合约部署者验证源代码才能查看",
                "rpc_method": "eth_getCode (只能获取字节码，不是源代码)"
            },
            "arbitrum": {
                "can_query": True,
                "method": "通过区块浏览器（Arbiscan）查看已验证的合约源代码",
                "explorer": "https://arbiscan.io/address/{address}#code",
                "note": "需要合约部署者验证源代码才能查看",
                "rpc_method": "eth_getCode (只能获取字节码，不是源代码)"
            },
            "optimism": {
                "can_query": True,
                "method": "通过区块浏览器（Optimistic Etherscan）查看已验证的合约源代码",
                "explorer": "https://optimistic.etherscan.io/address/{address}#code",
                "note": "需要合约部署者验证源代码才能查看",
                "rpc_method": "eth_getCode (只能获取字节码，不是源代码)"
            },
            "avalanche": {
                "can_query": True,
                "method": "通过区块浏览器（Snowtrace）查看已验证的合约源代码",
                "explorer": "https://snowtrace.io/address/{address}#code",
                "note": "需要合约部署者验证源代码才能查看",
                "rpc_method": "eth_getCode (只能获取字节码，不是源代码)"
            },
            # Sui：Move语言，合约代码存储在链上，可以直接查询
            "sui": {
                "can_query": True,
                "method": "通过RPC直接查询Move模块源代码（存储在链上）",
                "explorer": "https://suiexplorer.com/object/{address}",
                "note": "Sui的Move合约代码完全存储在链上，可以通过RPC查询",
                "rpc_method": "sui_getNormalizedMoveModule 或 sui_getNormalizedMoveModulesByPackage"
            },
            # Solana：程序代码存储在链上，但可能不是人类可读的格式
            "solana": {
                "can_query": True,
                "method": "通过RPC查询程序账户数据（BPF字节码）",
                "explorer": "https://explorer.solana.com/address/{address}",
                "note": "可以获取程序账户数据，但SPL代币通常是标准程序，源代码需要从其他地方获取",
                "rpc_method": "getAccountInfo (获取程序账户数据，是编译后的BPF字节码)"
            }
        },
        "summary": "EVM链需要合约验证源代码才能查看；Sui可以直接通过RPC查询；Solana可以获取字节码"
    }

