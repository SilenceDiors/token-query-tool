"""
抑制不必要的警告信息
"""
import warnings

# 抑制urllib3的OpenSSL警告
warnings.filterwarnings('ignore', message='.*urllib3 v2 only supports OpenSSL.*')

