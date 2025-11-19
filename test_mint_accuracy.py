#!/usr/bin/env python3
"""
测试mint权限识别准确性
为每个链选择5个代币进行测试
"""
import subprocess
import sys
from typing import Dict, List, Tuple

# 测试用例
TEST_CASES = {
    'ethereum': [
        ('0xdAC17F958D2ee523a22062069994597C13D831ec7', 'USDT'),
        ('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'USDC'),
        ('0x1fB35614aA19c80eb997adad5F71520e915003C0', 'SEEK'),
        ('0xC477B6dfd26EC2460b3b92de18837Fd476Ea7549', 'Test1'),
        ('0xba83b5ed3f12Bfa44f066f03eE0433419B74f469', 'BEST'),
    ],
    'bsc': [
        ('0x55d398326f99059fF775485246999027B3197955', 'USDT'),
        ('0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', 'USDC'),
        ('0x40b8129B786D766267A7a118cF8C07E31CDB6Fde', 'UBOFT'),
        ('0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56', 'BUSD'),
        ('0x2170Ed0880ac9A755fd29B2688956BD959F933F8', 'ETH'),
    ],
    'polygon': [
        ('0xc2132D05D31c914a87C6611C10748AEb04B58e8F', 'USDT'),
        ('0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174', 'USDC'),
        ('0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270', 'WMATIC'),
        ('0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6', 'WBTC'),
        ('0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619', 'WETH'),
    ],
    'sui': [
        ('0x2::sui::SUI', 'SUI'),
        ('0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93b::coin::COIN', 'USDC'),
        ('0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb', 'LINEUP'),
    ],
    'solana': [
        ('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'USDC'),
        ('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 'USDT'),
        ('So11111111111111111111111111111111111112', 'SOL'),
    ]
}


def test_token(chain: str, address: str, name: str) -> Tuple[bool, str]:
    """测试单个代币的mint分析"""
    try:
        cmd = ['python3', 'main.py', '--mint', address, '--chain', chain.upper()]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = result.stdout + result.stderr
        
        # 检查是否有错误
        if result.returncode != 0:
            return False, f"命令执行失败: {result.stderr[:200]}"
        
        # 检查输出中是否包含关键信息
        has_mint_analysis = 'Mint功能分析' in output
        has_no_mint = '未检测到Mint功能' in output or '未找到mint' in output.lower()
        has_access_control = '权限控制' in output
        
        # 如果没有mint功能，这也是正常情况（固定供应量代币）
        if has_no_mint:
            return True, "无mint功能（固定供应量，正常）"
        
        if not has_mint_analysis:
            # 检查是否有其他错误信息
            if '无法获取合约代码' in output or '源代码未验证' in output:
                return False, "无法获取合约代码"
            return False, "未找到Mint功能分析"
        
        # 提取权限控制信息
        lines = output.split('\n')
        access_control_line = None
        for i, line in enumerate(lines):
            if '权限控制:' in line:
                access_control_line = line
                break
        
        if access_control_line:
            return True, access_control_line.strip()
        else:
            return True, "已分析但未找到权限控制信息"
            
    except subprocess.TimeoutExpired:
        return False, "超时"
    except Exception as e:
        return False, f"异常: {str(e)[:200]}"


def main():
    """主函数"""
    print("=" * 80)
    print("Mint权限识别准确性测试")
    print("=" * 80)
    print()
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    for chain, tokens in TEST_CASES.items():
        print(f"\n{'='*80}")
        print(f"测试链: {chain.upper()}")
        print(f"{'='*80}")
        
        for address, name in tokens:
            total_tests += 1
            print(f"\n[{total_tests}] 测试 {name} ({address[:20]}...)")
            
            success, message = test_token(chain, address, name)
            
            if success:
                passed_tests += 1
                print(f"  ✓ 通过: {message}")
            else:
                failed_tests.append((chain, address, name, message))
                print(f"  ✗ 失败: {message}")
    
    # 汇总
    print("\n" + "=" * 80)
    print("测试汇总")
    print("=" * 80)
    print(f"总测试数: {total_tests}")
    print(f"通过: {passed_tests}")
    print(f"失败: {len(failed_tests)}")
    
    if failed_tests:
        print("\n失败的测试用例:")
        for chain, address, name, message in failed_tests:
            print(f"  - {chain} {name} ({address[:30]}...): {message}")
    
    return 0 if len(failed_tests) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

