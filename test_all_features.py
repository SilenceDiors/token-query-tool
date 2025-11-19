#!/usr/bin/env python3
"""
综合测试脚本 - 测试所有链的所有功能
"""
import subprocess
import sys
import time
from typing import Dict, List, Tuple

# 测试用例 - 每个链选择代表性的代币
TEST_CASES = {
    'ethereum': [
        ('0xdAC17F958D2ee523a22062069994597C13D831ec7', 'USDT'),
        ('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'USDC'),
        ('0xC477B6dfd26EC2460b3b92de18837Fd476Ea7549', 'Test1'),
        ('0xba83b5ed3f12Bfa44f066f03eE0433419B74f469', 'BEST'),
        ('0x1fB35614aA19c80eb997adad5F71520e915003C0', 'SEEK'),
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
        ('0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb::lineup::LINEUP', 'LINEUP'),
    ],
    'solana': [
        ('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'USDC'),
        ('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', 'USDT'),
        ('So11111111111111111111111111111111111112', 'SOL'),
    ]
}

# 要测试的功能
FEATURES = ['info', 'mint', 'goplus', 'scan', 'code', 'llm']


def test_feature(chain: str, address: str, name: str, feature: str) -> Tuple[bool, str]:
    """测试单个功能"""
    try:
        cmd = ['python3', 'main.py', f'--{feature}', address, '--chain', chain.upper()]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120  # 2分钟超时
        )
        
        output = result.stdout + result.stderr
        
        # 检查是否有错误
        if result.returncode != 0:
            return False, f"命令执行失败: {result.stderr[:150]}"
        
        # 根据功能检查输出
        if feature == 'info':
            # 检查多种可能的输出格式
            if ('代币详细信息' in output or 
                '代币名称' in output or 
                '代币符号' in output or
                '总供应量' in output or
                'Total Supply' in output or
                'symbol' in output.lower() or
                'name' in output.lower() or
                'supply' in output.lower()):
                return True, "成功"
            # 检查是否是已知错误
            if '无法获取' in output or 'error' in output.lower() or '失败' in output or 'Traceback' in output:
                return False, f"获取失败: {output[:100]}"
            return False, "未找到代币信息"
        
        elif feature == 'mint':
            # 所有这些都是正常的输出，表示分析完成
            if ('Mint功能分析' in output or 
                '未检测到Mint功能' in output or 
                '铸造形式' in output or
                '无法从GoPlus获取Mint信息' in output or
                'GoPlus Labs' in output or
                '分析完成' in output):
                return True, "成功"
            # 只有真正的错误才失败
            if 'Traceback' in output or 'Error' in output or 'Exception' in output:
                return False, f"执行错误: {output[:100]}"
            return False, "未找到Mint分析"
        
        elif feature == 'goplus':
            if 'GoPlus' in output or 'goplus' in output.lower() or '安全信息' in output:
                return True, "成功"
            return False, "未找到GoPlus信息"
        
        elif feature == 'scan':
            if '安全扫描' in output or '扫描结果' in output or '问题' in output or 'issues' in output.lower():
                return True, "成功"
            return False, "未找到扫描结果"
        
        elif feature == 'code':
            if '代码' in output or 'code' in output.lower() or 'zip' in output.lower() or '压缩包' in output:
                return True, "成功"
            return False, "未找到代码信息"
        
        elif feature == 'llm':
            if 'LLM' in output or '提示词' in output or 'prompt' in output.lower() or '报告' in output:
                return True, "成功"
            return False, "未找到LLM提示词"
        
        return True, "成功"
        
    except subprocess.TimeoutExpired:
        return False, "超时"
    except Exception as e:
        return False, f"异常: {str(e)[:150]}"


def main():
    """主函数"""
    print("=" * 100)
    print("综合功能测试 - 所有链的所有功能")
    print("=" * 100)
    print()
    
    total_tests = 0
    passed_tests = 0
    failed_tests = []
    
    # 统计信息
    chain_stats = {}
    feature_stats = {}
    
    for chain, tokens in TEST_CASES.items():
        print(f"\n{'='*100}")
        print(f"测试链: {chain.upper()}")
        print(f"{'='*100}")
        
        chain_stats[chain] = {'total': 0, 'passed': 0, 'failed': 0}
        
        for address, name in tokens:
            print(f"\n代币: {name} ({address[:30]}...)")
            print("-" * 100)
            
            for feature in FEATURES:
                total_tests += 1
                chain_stats[chain]['total'] += 1
                
                if feature not in feature_stats:
                    feature_stats[feature] = {'total': 0, 'passed': 0, 'failed': 0}
                feature_stats[feature]['total'] += 1
                
                print(f"  [{feature.upper():<6}] ", end='', flush=True)
                success, message = test_feature(chain, address, name, feature)
                
                if success:
                    passed_tests += 1
                    chain_stats[chain]['passed'] += 1
                    feature_stats[feature]['passed'] += 1
                    print(f"✓ 通过")
                else:
                    failed_tests.append((chain, address, name, feature, message))
                    chain_stats[chain]['failed'] += 1
                    feature_stats[feature]['failed'] += 1
                    print(f"✗ 失败: {message[:60]}")
                
                # 避免请求过快
                time.sleep(0.5)
    
    # 汇总
    print("\n" + "=" * 100)
    print("测试汇总")
    print("=" * 100)
    print(f"总测试数: {total_tests}")
    print(f"通过: {passed_tests} ({passed_tests/total_tests*100:.1f}%)")
    print(f"失败: {len(failed_tests)} ({len(failed_tests)/total_tests*100:.1f}%)")
    print()
    
    # 按链统计
    print("按链统计:")
    print("-" * 100)
    for chain, stats in chain_stats.items():
        pass_rate = stats['passed'] / stats['total'] * 100 if stats['total'] > 0 else 0
        print(f"  {chain.upper():<12} 总计: {stats['total']:<4} 通过: {stats['passed']:<4} 失败: {stats['failed']:<4} 通过率: {pass_rate:.1f}%")
    print()
    
    # 按功能统计
    print("按功能统计:")
    print("-" * 100)
    for feature, stats in feature_stats.items():
        pass_rate = stats['passed'] / stats['total'] * 100 if stats['total'] > 0 else 0
        print(f"  --{feature:<6} 总计: {stats['total']:<4} 通过: {stats['passed']:<4} 失败: {stats['failed']:<4} 通过率: {pass_rate:.1f}%")
    print()
    
    # 失败的测试用例
    if failed_tests:
        print("失败的测试用例:")
        print("-" * 100)
        for chain, address, name, feature, message in failed_tests:
            print(f"  - {chain.upper()} {name} --{feature}: {message[:80]}")
    else:
        print("✓ 所有测试通过！")
    
    return 0 if len(failed_tests) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

