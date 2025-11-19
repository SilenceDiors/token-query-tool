#!/usr/bin/env python3
"""
测试 Sui mint 功能分析 - 10个测试用例
"""
import subprocess
import sys
import json
from typing import Dict, List, Tuple

# 10个 Sui 代币测试用例
TEST_CASES = [
    ('0x87dfe1248a1dc4ce473bd9cb2937d66cdc6c30fee63f3fe0dbb55c7a09d35dec::up::UP', 'UP'),
    ('0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb::lineup::LINEUP', 'LINEUP'),
    ('0xe03aa7dc69ba3f8d8876d24bd61b79f31bff3a82d18100bcae903b9fdf4058a2::artis::ARTIS', 'ARTIS'),
    ('0x2::sui::SUI', 'SUI'),
    ('0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93b::coin::COIN', 'USDC'),
    ('0xaf8cd5edc19c4512f4259f0bee101a40df44f2fe20d89518df35b0c83071a8a::movexnft::MovexNFT', 'MovexNFT'),
    ('0x2::sui::SUI', 'SUI_Native'),
    ('0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93b::coin::COIN', 'USDC_Sui'),
    ('0x2::sui::SUI', 'SUI_Test'),
    ('0x03cd711c02597eba9e20f04cb8eee214c23229605faaaa717eafbbbdee55ccfb', 'LINEUP_Short'),
]

def test_token(address: str, name: str) -> Tuple[bool, str, Dict]:
    """测试单个代币的mint分析"""
    try:
        result = subprocess.run(
            ['python3', 'main.py', '--mint', address],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout + result.stderr
        
        # 检查是否成功
        success = result.returncode == 0
        
        # 提取关键信息
        info = {
            'has_mint_analysis': 'Mint功能分析' in output,
            'has_max_supply': '最大值限制' in output,
            'has_access_control': '权限控制' in output,
            'code_incomplete': '代码不完整' in output or '无法确定' in output,
            'error': None
        }
        
        # 检查是否有错误
        if '无法获取合约代码' in output or '分析失败' in output:
            info['error'] = '无法获取代码或分析失败'
            success = False
        
        # 提取具体信息
        if '最大值限制:' in output:
            max_supply_line = [line for line in output.split('\n') if '最大值限制:' in line]
            if max_supply_line:
                info['max_supply_text'] = max_supply_line[0].strip()
        
        if '权限控制:' in output:
            access_line = [line for line in output.split('\n') if '权限控制:' in line]
            if access_line:
                info['access_control_text'] = access_line[0].strip()
        
        message = "成功" if success and info['has_mint_analysis'] else "失败"
        if info.get('error'):
            message = info['error']
        
        return success and info['has_mint_analysis'], message, info
        
    except subprocess.TimeoutExpired:
        return False, "超时", {'error': 'timeout'}
    except Exception as e:
        return False, f"异常: {str(e)[:100]}", {'error': str(e)}


def main():
    """主函数"""
    print("=" * 80)
    print("Sui Mint 功能分析测试 - 10个测试用例")
    print("=" * 80)
    print()
    
    results = []
    total_tests = len(TEST_CASES)
    passed_tests = 0
    
    for i, (address, name) in enumerate(TEST_CASES, 1):
        print(f"\n[{i}/{total_tests}] 测试 {name}")
        print(f"地址: {address[:50]}...")
        
        success, message, info = test_token(address, name)
        results.append({
            'name': name,
            'address': address,
            'success': success,
            'message': message,
            'info': info
        })
        
        if success:
            passed_tests += 1
            print(f"  ✓ 通过: {message}")
            if 'max_supply_text' in info:
                print(f"    最大值限制: {info['max_supply_text']}")
            if 'access_control_text' in info:
                print(f"    权限控制: {info['access_control_text']}")
        else:
            print(f"  ✗ 失败: {message}")
            if info.get('error'):
                print(f"    错误: {info['error']}")
    
    # 汇总
    print("\n" + "=" * 80)
    print("测试汇总")
    print("=" * 80)
    print(f"总测试数: {total_tests}")
    print(f"通过: {passed_tests}")
    print(f"失败: {total_tests - passed_tests}")
    print(f"成功率: {passed_tests/total_tests*100:.1f}%")
    
    # 失败的测试用例
    failed = [r for r in results if not r['success']]
    if failed:
        print("\n失败的测试用例:")
        for r in failed:
            print(f"  - {r['name']}: {r['message']}")
            if r['info'].get('error'):
                print(f"    错误: {r['info']['error']}")
    
    # 保存结果到文件
    with open('test_sui_mint_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n结果已保存到: test_sui_mint_results.json")
    
    return 0 if len(failed) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

