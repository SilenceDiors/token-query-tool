"""
格式化工具函数
"""
from typing import Optional


def format_supply(value: Optional[str], decimals: int = 0) -> str:
    """格式化供应量"""
    if value is None:
        return "N/A"
    
    try:
        supply_int = int(value)
        supply = supply_int / (10 ** decimals)
        if decimals == 0:
            return f"{supply:,.0f}"
        elif supply >= 1_000_000:
            return f"{supply:,.0f}"
        elif supply >= 1_000:
            return f"{supply:,.2f}"
        else:
            return f"{supply:,.{decimals}f}"
    except:
        return str(value)


def print_separator():
    """打印分隔线"""
    print("=" * 80)


def print_table(data: list, headers: list = None):
    """打印表格"""
    if not data:
        return
    
    if headers:
        all_rows = [headers] + data
    else:
        all_rows = data
    
    # 计算每列的最大宽度
    col_widths = []
    for i in range(len(all_rows[0])):
        col_width = max(len(str(row[i])) for row in all_rows)
        col_widths.append(col_width)
    
    # 打印表头
    if headers:
        header_row = " | ".join(str(headers[i]).ljust(col_widths[i]) for i in range(len(headers)))
        print(header_row)
        print("-" * len(header_row))
    
    # 打印数据行
    start_idx = 1 if headers else 0
    for row in all_rows[start_idx:]:
        data_row = " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(row)))
        print(data_row)

